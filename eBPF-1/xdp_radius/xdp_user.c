#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MAX_VLAN_MAP 64
#define MAX_IFACE_LEN 16

struct authentication{
    uint16_t vlan_id;
    uint8_t state;      
    uint8_t enforced;     
    uint32_t ifindex;    
    uint64_t last_seen_ns;
} __attribute__((packed));

struct vlan_mapping {
    uint16_t vlan_id;
    char iface[MAX_IFACE_LEN];
};

struct config {
    char bridge[MAX_IFACE_LEN];
    char gateway_iface[MAX_IFACE_LEN];
    char map_path[256];
    uint64_t interval_ms;
    struct vlan_mapping vlan_map[MAX_VLAN_MAP];
    int vlan_map_count;
    int log_level; // 0=error, 1=warn, 2=info, 3=debug
};

static struct config cfg;

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

static int run_cmd(const char *cmd, char *const argv[]) {
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
        log(LOG_ERROR, "command failed: %s", cmd);
        return -1;
    }
    
    return 0;
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
    
    log(LOG_DEBUG, "remove VID %u on %s", vid, iface);
    
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

static int allow_mac_on_iface(const uint8_t *mac, const char *iface) {
    char mac_str[18];
    mac_to_string(mac, mac_str, sizeof(mac_str));
    
    log(LOG_INFO, "allow MAC %s on %s", mac_str, iface);
    
    // Ingress rule
    char *argv1[] = {
        "ebtables", "-A", "FORWARD", "-i", (char*)iface,
        "-s", mac_str, "-j", "ACCEPT", NULL
    };
    if (run_cmd("ebtables", argv1) != 0) return -1;
    
    // Egress rule
    char *argv2[] = {
        "ebtables", "-A", "FORWARD", "-o", (char*)iface,
        "-d", mac_str, "-j", "ACCEPT", NULL
    };
    return run_cmd("ebtables", argv2);
}

static int revoke_mac_on_iface(const uint8_t *mac, const char *iface) {
    char mac_str[18];
    mac_to_string(mac, mac_str, sizeof(mac_str));
    
    log(LOG_INFO, "revoke MAC %s on %s", mac_str, iface);
    
    char *argv1[] = {
        "ebtables", "-D", "FORWARD", "-i", (char*)iface,
        "-s", mac_str, "-j", "ACCEPT", NULL
    };
    run_cmd("ebtables", argv1); // ignore errors
    
    char *argv2[] = {
        "ebtables", "-D", "FORWARD", "-o", (char*)iface,
        "-d", mac_str, "-j", "ACCEPT", NULL
    };
    run_cmd("ebtables", argv2); // ignore errors
    
    return 0;
}

static const char* find_iface_for_vlan(uint16_t vlan_id) {
    for (int i = 0; i < cfg.vlan_map_count; i++) {
        if (cfg.vlan_map[i].vlan_id == vlan_id) {
            return cfg.vlan_map[i].iface;
        }
    }
    return NULL;
}

static int parse_vlan_map(const char *s) {
    char *copy = strdup(s);
    char *token = strtok(copy, ",");
    
    cfg.vlan_map_count = 0;
    
    while (token && cfg.vlan_map_count < MAX_VLAN_MAP) {
        char *colon = strchr(token, ':');
        if (!colon) {
            log(LOG_ERROR, "invalid vlan_map item: %s", token);
            free(copy);
            return -1;
        }
        
        *colon = '\0';
        uint16_t vid = atoi(token);
        const char *iface = colon + 1;
        
        if (strlen(iface) == 0 || strlen(iface) >= MAX_IFACE_LEN) {
            log(LOG_ERROR, "invalid iface in vlan_map: %s", iface);
            free(copy);
            return -1;
        }
        
        cfg.vlan_map[cfg.vlan_map_count].vlan_id = vid;
        strncpy(cfg.vlan_map[cfg.vlan_map_count].iface, iface, MAX_IFACE_LEN - 1);
        cfg.vlan_map_count++;
        
        token = strtok(NULL, ",");
    }
    
    free(copy);
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  --bridge BRIDGE         (default: br0)\n");
    fprintf(stderr, "  --vlan-map MAP          e.g., 32:eth1,95:eth2\n");
    fprintf(stderr, "  --map-path PATH         (default: /sys/fs/bpf/auth_map)\n");
    fprintf(stderr, "  --gateway-iface IFACE   (default: eth0)\n");
    fprintf(stderr, "  --interval-ms MS        (default: 200)\n");
    fprintf(stderr, "  --log-level LEVEL       0-3 (default: 2=info)\n");
}

int main(int argc, char **argv) {
    // Default config
    strncpy(cfg.bridge, "br0", sizeof(cfg.bridge));
    strncpy(cfg.gateway_iface, "eth0", sizeof(cfg.gateway_iface));
    strncpy(cfg.map_path, "/sys/fs/bpf/auth_map", sizeof(cfg.map_path));
    cfg.interval_ms = 200;
    cfg.log_level = LOG_INFO;
    cfg.vlan_map_count = 0;
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bridge") == 0 && i + 1 < argc) {
            strncpy(cfg.bridge, argv[++i], sizeof(cfg.bridge) - 1);
        } else if (strcmp(argv[i], "--vlan-map") == 0 && i + 1 < argc) {
            if (parse_vlan_map(argv[++i]) != 0) {
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
    
    if (cfg.vlan_map_count == 0) {
        log(LOG_ERROR, "vlan_map is required");
        print_usage(argv[0]);
        return 1;
    }
    
    log(LOG_INFO, "xdp_user start: bridge=%s, gateway_iface=%s, map_path=%s, interval=%lums",
        cfg.bridge, cfg.gateway_iface, cfg.map_path, cfg.interval_ms);
    
    ensure_bridge_vlan_filtering(cfg.bridge);
    
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
    
    uint8_t mac_key[6];
    struct authentication val;
    uint8_t next_key[6];
    int first = 1;
    
    while (1) {
        log(LOG_DEBUG, "polling auth_map...");
        
        memset(mac_key, 0, sizeof(mac_key));
        first = 1;
        
        while (1) {
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
            
            const char *iface = find_iface_for_vlan(val.vlan_id);
            if (!iface) {
                char mac_str[18];
                mac_to_string(mac_key, mac_str, sizeof(mac_str));
                log(LOG_WARN, "no iface mapping for VLAN %u (mac=%s)", val.vlan_id, mac_str);
                continue;
            }
            
            char mac_str[18];
            mac_to_string(mac_key, mac_str, sizeof(mac_str));
            
            if (val.state == 1 && val.enforced == 0) {
                log(LOG_INFO, "ACCEPT %s vlan %u -> %s", mac_str, val.vlan_id, iface);
                
                if (enable_vlan(iface, cfg.gateway_iface, val.vlan_id) == 0 &&
                    allow_mac_on_iface(mac_key, iface) == 0) {
                    val.enforced = 1;
                    bpf_map_update_elem(map_fd, mac_key, &val, BPF_ANY);
                }
            } else if (val.state == 0 && val.enforced == 1) {
                log(LOG_INFO, "REVOKE %s vlan %u -> %s", mac_str, val.vlan_id, iface);
                
                revoke_mac_on_iface(mac_key, iface);
                disable_vlan(iface, cfg.gateway_iface, val.vlan_id);
                
                //val.enforced = 0;
                //bpf_map_update_elem(map_fd, mac_key, &val, BPF_ANY);
                bpf_map_delete_elem(map_fd, mac_key);
                log(LOG_DEBUG, "deleted auth_map entry for %s", mac_str);
            } else {
                log(LOG_DEBUG, "noop for %s: state=%u, enforced=%u, vlan=%u",
                    mac_str, val.state, val.enforced, val.vlan_id);
            }
        }
        
        usleep(cfg.interval_ms * 1000);
    }
    
    close(map_fd);
    return 0;
}