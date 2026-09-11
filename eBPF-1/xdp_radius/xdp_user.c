/*
 * xdp_user — enforcer userspace per l'autenticazione 802.1X con XDP (Site 2).
 *
 * Polla la mappa pinnata auth_map e traduce le decisioni dell'XDP in regole
 * L2 (bridge vlan + ebtables).
 *
 * Scelte di progetto:
 *  - la porta client NON e' configurata staticamente: arriva dal campo
 *    ingress_port_idx scritto dall'XDP EAPOL al momento della claim e viene
 *    tradotta in nome interfaccia con if_indextoname(); la whitelist VLAN
 *    (--vlans) fa solo da controllo di ammissibilita';
 *  - SIGINT/SIGTERM gestiti: uscita pulita con chiusura dei fd;
 *  - regole ebtables idempotenti (check -C prima di -A): un riavvio del
 *    daemon con regole gia' presenti non accumula duplicati;
 *  - sweep periodico delle claim scadute in identity_map (TTL allineato al
 *    programma BPF: vedere IDENTITY_TTL_NS in xdp_prog_kern.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MAX_VLANS 64
#define MAX_IFACE_LEN 16
#define IDENTITY_MAP_PATH "/sys/fs/bpf/identity_map"

/* --- layout e costanti allineati al lato BPF --- */
#define ID_MAX 64                                  /* sync: xdp_common.h */
#define IDENTITY_TTL_NS (15ULL * 1000000000ULL)    /* sync: xdp_prog_kern.c */
#define REAP_EVERY_POLLS 25                        /* 25 * 200 ms = 5 s */

struct auth_identity {
    char identity[ID_MAX];
};

struct supplicant_claim {
    uint8_t sta_mac[6];
    uint32_t ingress_port_idx;
    uint64_t claimed_at_ns;
};

struct authentication {
    uint16_t vlan_id;
    uint8_t state;
    uint8_t enforced;
    uint32_t ifindex;
    uint64_t last_seen_ns;
} __attribute__((packed));

struct config {
    char bridge[MAX_IFACE_LEN];
    char gateway_iface[MAX_IFACE_LEN];
    char map_path[256];
    uint64_t interval_ms;
    uint16_t vlans[MAX_VLANS];
    int vlans_count;
    int log_level; // 0=error, 1=warn, 2=info, 3=debug
};

static struct config cfg;
static volatile sig_atomic_t g_stop = 0;

#define LOG_ERROR 0
#define LOG_WARN 1
#define LOG_INFO 2
#define LOG_DEBUG 3

#define log(level, fmt, ...) do { \
    if (cfg.log_level >= level) { \
        time_t t = time(NULL); \
        char buf[32]; \
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t)); \
        fprintf(stderr, "[%s] " fmt "\n", buf, ##__VA_ARGS__); \
    } \
} while(0)

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* fork+exec+wait; quiet=1 sopprime il log d'errore (usato per i check) */
static int spawn_wait(const char *cmd, char *const argv[], int quiet)
{
    if (!quiet)
        log(LOG_DEBUG, "exec: %s", cmd);

    pid_t pid = fork();
    if (pid < 0) {
        log(LOG_ERROR, "fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        execvp(cmd, argv);
        exit(1);
    }

    int status;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (!quiet)
            log(LOG_ERROR, "command failed: %s", cmd);
        return -1;
    }

    return 0;
}

static int run_cmd(const char *cmd, char *const argv[])
{
    return spawn_wait(cmd, argv, 0);
}

static int ensure_bridge_vlan_filtering(const char *bridge) {
    log(LOG_INFO, "enabling VLAN filtering on bridge %s", bridge);

    char *argv[] = {
        "ip", "link", "set", "dev", (char*)bridge,
        "type", "bridge", "vlan_filtering", "1", NULL
    };

    run_cmd("ip", argv); // ignore errors
    return 0;
}

static int enable_vlan(const char *iface, const char *gw_iface, uint16_t vid) {
    char vid_str[8];
    snprintf(vid_str, sizeof(vid_str), "%u", vid);

    log(LOG_DEBUG, "set PVID %u (untagged) on %s", vid, iface);

    char *argv1[] = {
        "bridge", "vlan", "add", "dev", (char*)iface,
        "vid", vid_str, "pvid", "untagged", NULL
    };
    if (run_cmd("bridge", argv1) != 0) return -1;

    char *argv2[] = {
        "bridge", "vlan", "add", "dev", (char*)gw_iface,
        "vid", vid_str, NULL
    };
    return run_cmd("bridge", argv2);
}

static int disable_vlan(const char *iface, const char *gw_iface, uint16_t vid) {
    char vid_str[8];
    snprintf(vid_str, sizeof(vid_str), "%u", vid);

    log(LOG_DEBUG, "remove VID %u on %s", vid, gw_iface);

    char *argv[] = {
        "bridge", "vlan", "del", "dev", (char*)gw_iface,
        "vid", vid_str, NULL
    };

    run_cmd("bridge", argv); // ignore errors
    return 0;
}

static void mac_to_string(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* idempotente: -C (check) prima di -A, per non accumulare duplicati
 * quando il daemon riparte dopo un crash con regole gia' in tabella */
static int allow_mac_on_iface(const uint8_t *mac, const char *iface) {
    char mac_str[18];
    mac_to_string(mac, mac_str, sizeof(mac_str));

    log(LOG_INFO, "allow MAC %s on %s", mac_str, iface);

    char *chk_i[] = {
        "ebtables", "-C", "FORWARD", "-i", (char*)iface,
        "-s", mac_str, "-j", "ACCEPT", NULL
    };
    if (spawn_wait("ebtables", chk_i, 1) != 0) {
        char *add_i[] = {
            "ebtables", "-A", "FORWARD", "-i", (char*)iface,
            "-s", mac_str, "-j", "ACCEPT", NULL
        };
        if (spawn_wait("ebtables", add_i, 0) != 0) return -1;
    }

    char *chk_o[] = {
        "ebtables", "-C", "FORWARD", "-o", (char*)iface,
        "-d", mac_str, "-j", "ACCEPT", NULL
    };
    if (spawn_wait("ebtables", chk_o, 1) != 0) {
        char *add_o[] = {
            "ebtables", "-A", "FORWARD", "-o", (char*)iface,
            "-d", mac_str, "-j", "ACCEPT", NULL
        };
        if (spawn_wait("ebtables", add_o, 0) != 0) return -1;
    }

    return 0;
}

static int revoke_mac_on_iface(const uint8_t *mac, const char *iface) {
    char mac_str[18];
    mac_to_string(mac, mac_str, sizeof(mac_str));

    log(LOG_INFO, "revoke MAC %s on %s", mac_str, iface);

    char *argv1[] = {
        "ebtables", "-D", "FORWARD", "-i", (char*)iface,
        "-s", mac_str, "-j", "ACCEPT", NULL
    };
    spawn_wait("ebtables", argv1, 1); // ignore errors

    char *argv2[] = {
        "ebtables", "-D", "FORWARD", "-o", (char*)iface,
        "-d", mac_str, "-j", "ACCEPT", NULL
    };
    spawn_wait("ebtables", argv2, 1); // ignore errors

    return 0;
}

static int vlan_allowed(uint16_t vid) {
    for (int i = 0; i < cfg.vlans_count; i++) {
        if (cfg.vlans[i] == vid)
            return 1;
    }
    return 0;
}

/* la porta client NON e' in configurazione: e' l'ifindex di ingresso
 * dell'EAPOL, registrato dall'XDP nella claim (fonte verita' = il filo) */
static const char *iface_from_ifindex(uint32_t idx, char *buf, size_t len)
{
    if (idx == 0 || if_indextoname(idx, buf) == NULL)
        return NULL;
    buf[len - 1] = '\0';
    return buf;
}

static int parse_vlans(const char *s) {
    char *copy = strdup(s);
    char *token = strtok(copy, ",");

    cfg.vlans_count = 0;

    while (token && cfg.vlans_count < MAX_VLANS) {
        int vid = atoi(token);
        if (vid < 1 || vid > 4094) {
            log(LOG_ERROR, "invalid VLAN in whitelist: %s", token);
            free(copy);
            return -1;
        }

        cfg.vlans[cfg.vlans_count++] = (uint16_t)vid;
        token = strtok(NULL, ",");
    }

    free(copy);
    return 0;
}

/* rimuove da identity_map le claim piu' vecchie del TTL: senza sweep una
 * claim non consumata (es. Accept mai arrivato) resterebbe in mappa fino
 * all'evizione LRU. Pattern di iterazione: dopo la delete il pivot resta
 * sul precedente elemento esistente, cosi' get_next_key avanza comunque */
static void reap_identity_map(int map_fd)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    struct auth_identity prev, next;
    struct supplicant_claim claim;
    int have_prev = 0;
    int removed = 0;

    memset(&prev, 0, sizeof(prev));

    for (int guard = 0; guard < 4096; guard++) {
        int ret = have_prev ? bpf_map_get_next_key(map_fd, &prev, &next)
                            : bpf_map_get_next_key(map_fd, NULL, &next);
        if (ret != 0)
            break; /* mappa finita */

        if (bpf_map_lookup_elem(map_fd, &next, &claim) != 0) {
            prev = next;
            have_prev = 1;
            continue;
        }

        if (now - claim.claimed_at_ns > IDENTITY_TTL_NS) {
            bpf_map_delete_elem(map_fd, &next);
            removed++;
            log(LOG_DEBUG, "reaped stale identity claim (age > TTL)");
            continue; /* pivot invariato: avanza comunque */
        }

        prev = next;
        have_prev = 1;
    }

    if (removed)
        log(LOG_INFO, "identity reaper: removed %d stale claim(s)", removed);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  --bridge BRIDGE         (default: bridge0)\n");
    fprintf(stderr, "  --vlans LIST            allowed VLANs, e.g. 10,20\n");
    fprintf(stderr, "  --map-path PATH         (default: /sys/fs/bpf/auth_map)\n");
    fprintf(stderr, "  --gateway-iface IFACE   (default: eth0)\n");
    fprintf(stderr, "  --interval-ms MS        (default: 200)\n");
    fprintf(stderr, "  --log-level LEVEL       0-3 (default: 2=info)\n");
}

int main(int argc, char **argv) {
    // Default config
    strncpy(cfg.bridge, "bridge0", sizeof(cfg.bridge));
    strncpy(cfg.gateway_iface, "eth0", sizeof(cfg.gateway_iface));
    strncpy(cfg.map_path, "/sys/fs/bpf/auth_map", sizeof(cfg.map_path));
    cfg.interval_ms = 200;
    cfg.log_level = LOG_INFO;
    cfg.vlans_count = 0;

    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bridge") == 0 && i + 1 < argc) {
            strncpy(cfg.bridge, argv[++i], sizeof(cfg.bridge) - 1);
        } else if (strcmp(argv[i], "--vlans") == 0 && i + 1 < argc) {
            if (parse_vlans(argv[++i]) != 0) {
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--map-path") == 0 && i + 1 < argc) {
            strncpy(cfg.map_path, argv[++i], sizeof(cfg.map_path) - 1);
        } else if (strcmp(argv[i], "--gateway-iface") == 0 && i + 1 < argc) {
            strncpy(cfg.gateway_iface, argv[++i], sizeof(cfg.gateway_iface) - 1);
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            cfg.interval_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            char *level = argv[++i];
            if (strcmp(level, "error") == 0) cfg.log_level = 0;
            else if (strcmp(level, "warn") == 0) cfg.log_level = 1;
            else if (strcmp(level, "info") == 0) cfg.log_level = 2;
            else if (strcmp(level, "debug") == 0) cfg.log_level = 3;
            else cfg.log_level = atoi(level);
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (getuid() != 0) {
        log(LOG_ERROR, "run as root");
        return 1;
    }

    if (cfg.vlans_count == 0) {
        log(LOG_ERROR, "VLAN whitelist is required (--vlans)");
        print_usage(argv[0]);
        return 1;
    }

    log(LOG_INFO, "xdp_user start: bridge=%s, gateway_iface=%s, map_path=%s, "
        "vlans=%d, interval=%lums",
        cfg.bridge, cfg.gateway_iface, cfg.map_path,
        cfg.vlans_count, cfg.interval_ms);

    ensure_bridge_vlan_filtering(cfg.bridge);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct stat st;
    if (stat(cfg.map_path, &st) != 0) {
        log(LOG_ERROR, "map not found: %s", cfg.map_path);
        return 1;
    }

    log(LOG_INFO, "opening pinned map at %s", cfg.map_path);
    int map_fd = bpf_obj_get(cfg.map_path);
    if (map_fd < 0) {
        log(LOG_ERROR, "failed to open pinned map: %s", strerror(errno));
        return 1;
    }

    /* la mappa delle claim e' opzionale per l'enforcement: serve solo al
     * reaper. Se non c'e' si prosegue con un warning */
    int identity_fd = bpf_obj_get(IDENTITY_MAP_PATH);
    if (identity_fd < 0)
        log(LOG_WARN, "identity_map not available (%s): reaper disabled",
            IDENTITY_MAP_PATH);

    uint8_t mac_key[6];
    uint8_t next_key[6];
    struct authentication val;
    char iface_buf[MAX_IFACE_LEN];
    unsigned long polls = 0;
    int first;

    while (!g_stop) {
        polls++;

        if (identity_fd >= 0 && (polls % REAP_EVERY_POLLS) == 0)
            reap_identity_map(identity_fd);

        log(LOG_DEBUG, "polling auth_map...");

        memset(mac_key, 0, sizeof(mac_key));
        first = 1;

        while (!g_stop) {
            int ret;
            if (first) {
                ret = bpf_map_get_next_key(map_fd, NULL, next_key);
                first = 0;
            } else {
                ret = bpf_map_get_next_key(map_fd, mac_key, next_key);
            }

            if (ret != 0) break; // no more entries

            memcpy(mac_key, next_key, sizeof(mac_key));

            if (bpf_map_lookup_elem(map_fd, mac_key, &val) != 0) {
                log(LOG_WARN, "lookup failed for key");
                continue;
            }

            char mac_str[18];
            mac_to_string(mac_key, mac_str, sizeof(mac_str));

            if (val.state == 1 && val.enforced == 0) {
                if (!vlan_allowed(val.vlan_id)) {
                    log(LOG_WARN, "VLAN %u not whitelisted (mac=%s)",
                        val.vlan_id, mac_str);
                    continue;
                }

                const char *iface = iface_from_ifindex(val.ifindex,
                                                       iface_buf,
                                                       sizeof(iface_buf));
                if (!iface) {
                    log(LOG_WARN, "cannot resolve ingress ifindex %u (mac=%s)",
                        val.ifindex, mac_str);
                    continue;
                }
                if (strcmp(iface, cfg.gateway_iface) == 0) {
                    log(LOG_WARN, "claim points to gateway iface %s, skip "
                        "(mac=%s)", iface, mac_str);
                    continue;
                }

                log(LOG_INFO, "ACCEPT %s vlan %u -> %s",
                    mac_str, val.vlan_id, iface);

                if (enable_vlan(iface, cfg.gateway_iface, val.vlan_id) == 0 &&
                    allow_mac_on_iface(mac_key, iface) == 0) {
                    val.enforced = 1;
                    bpf_map_update_elem(map_fd, mac_key, &val, BPF_ANY);
                }
            } else if (val.state == 0 && val.enforced == 1) {
                const char *iface = iface_from_ifindex(val.ifindex,
                                                       iface_buf,
                                                       sizeof(iface_buf));
                if (!iface) {
                    log(LOG_WARN, "cannot resolve ingress ifindex %u (mac=%s)",
                        val.ifindex, mac_str);
                    bpf_map_delete_elem(map_fd, mac_key);
                    continue;
                }

                log(LOG_INFO, "REVOKE %s vlan %u -> %s",
                    mac_str, val.vlan_id, iface);

                revoke_mac_on_iface(mac_key, iface);
                disable_vlan(iface, cfg.gateway_iface, val.vlan_id);

                bpf_map_delete_elem(map_fd, mac_key);
                log(LOG_DEBUG, "deleted auth_map entry for %s", mac_str);
            } else {
                log(LOG_DEBUG, "noop for %s: state=%u, enforced=%u, vlan=%u",
                    mac_str, val.state, val.enforced, val.vlan_id);
            }
        }

        if (g_stop)
            break;

        usleep(cfg.interval_ms * 1000);
    }

    log(LOG_INFO, "shutting down");
    if (identity_fd >= 0)
        close(identity_fd);
    close(map_fd);
    return 0;
}
