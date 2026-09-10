/*
 * radius_xdp.c — programma XDP per l'enforcement 802.1X/RADIUS (Progetto #3).
 * Intercetta gli Access-Accept RADIUS, estrae MAC (attr 31, fallback attr 1)
 * e VLAN (attr 81) e li registra nella mappa auth_map per il controller.
 */

#include <stddef.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

/* helper eBPF dichiarati come puntatori (meccanismo di rilocazione di iproute2) */
static long (*bpf_map_update_elem)(const void *map, const void *key, const void *value,
                                   __u64 flags) = (void *)BPF_FUNC_map_update_elem;

/* i campi di rete vanno confrontati in host byte order */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__be16)(x)))
#else
#define bpf_htons(x) ((__be16)(__u16)(x))
#define bpf_ntohs(x) ((__u16)(__be16)(x))
#endif

#define RADIUS_AUTH_PORT                 1812  /* autenticazione */
#define RADIUS_ACCT_PORT                 1813  /* accounting */
#define RADIUS_CODE_ACCESS_ACCEPT        2     /* risposta "accesso consentito" */
#define RADIUS_HDR_LEN                   20    /* header RADIUS (RFC 2865) */
#define RADIUS_ATTR_USER_NAME            1     /* fallback per il MAC */
#define RADIUS_ATTR_CALLING_STATION_ID   31    /* MAC del supplicant */
#define RADIUS_ATTR_TUNNEL_PRIVATE_GROUP 81    /* VLAN assegnata (stringa) */
#define RADIUS_MAX_ATTRS                 32    /* loop limitato: lo esige il verifier */
#define MAC_ALEN                         6
#define MAC_STR_LEN                      17    /* "aa:bb:cc:dd:ee:ff" */
#define VLAN_STR_MAX                     4     /* fino a 4 cifre */
#define VLAN_ID_MAX                      4094  /* range VLAN valido */
#define RADIUS_MAX_PACKET                4096  /* lunghezza massima RADIUS (RFC 2865) */

/* chiave della mappa: MAC del client */
struct mac_key {
    __u8 addr[MAC_ALEN];
};

/* valore della mappa: VLAN assegnata e stato (1 = autenticato) */
struct auth_info {
    __u32 vlan_id;
    __u8 mac_addr[MAC_ALEN];
    __u8 status;
};

/* header RADIUS, 20 byte (RFC 2865); la lunghezza è nei due byte separati
 * perché bpf_ntohs (istruzione di byte-swap) fa perdere al verifier i bound
 * del registro e blocca l'aritmetica "puntatore pacchetto + scalare" */
struct radius_hdr {
    __u8 code;
    __u8 identifier;
    __u8 length_hi;
    __u8 length_lo;
    __u8 authenticator[16];
} __attribute__((packed));

/* definizione mappa nel formato legacy di iproute2 (sezione "maps"):
 * il nome della mappa per bpftool deriva dal nome del simbolo ("auth_map") */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") auth_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct mac_key),
    .value_size = sizeof(struct auth_info),
    .max_entries = 1024,
    .map_flags = 0,
};


char _license[] SEC("license") = "GPL";

/* carattere esadecimale -> valore, -1 se non valido */
static inline __attribute__((always_inline)) int hex_val(__u8 c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* due nibble consecutivi a offset costante -> byte, -1 se non esadecimale */
static inline __attribute__((always_inline)) int hex_byte(const __u8 *p, int off)
{
    int hi = hex_val(p[off]);
    int lo = hex_val(p[off + 1]);
    if (hi < 0 || lo < 0)
        return -1;
    return (__u8)((hi << 4) | lo);
}

static inline __attribute__((always_inline)) int is_mac_sep(__u8 c)
{
    return c == ':' || c == '-';
}

/* formato compatto "aabbccddeeff": 12 caratteri esadecimali consecutivi */
static inline __attribute__((always_inline)) int parse_mac_compact(const __u8 *p, struct mac_key *out)
{
#pragma unroll
    for (int k = 0; k < MAC_ALEN; k++) {
        int b = hex_byte(p, 2 * k);
        if (b < 0)
            return -1;
        out->addr[k] = (__u8)b;
    }
    return 0;
}

/* formato con separatori "aa:bb:cc:dd:ee:ff" / "aa-bb-cc-dd-ee-ff" */
static inline __attribute__((always_inline)) int parse_mac_sep(const __u8 *p, struct mac_key *out)
{
#pragma unroll
    for (int k = 0; k < MAC_ALEN; k++) {
        int b = hex_byte(p, 3 * k);
        if (b < 0)
            return -1;
        out->addr[k] = (__u8)b;
        if (k < MAC_ALEN - 1 && !is_mac_sep(p[3 * k + 2]))
            return -1;
    }
    return 0;
}

/*
 * MAC in formato compatto (12 caratteri) o con separatori (17). Offset
 * costanti e uscita IMMEDIATA al primo carattere non valido: un flag "ok"
 * vivo attraverso il loop e' un vettore di esplosione degli stati del
 * verifier (ogni combinazione valida/fallita diventa uno stato distinto).
 * Il chiamante ha gia' verificato la leggibilita' di MAC_STR_LEN byte.
 */
static inline __attribute__((always_inline)) int parse_mac(const __u8 *p, struct mac_key *out)
{
    if (parse_mac_compact(p, out) == 0)
        return 0;
    return parse_mac_sep(p, out);
}

/* stringa VLAN (max 4 cifre) -> numero, con validazione del range */
static inline __attribute__((always_inline)) int parse_vlan_id(const __u8 *p, const void *p_end, __u32 *out)
{
    __u32 val = 0;
    int digits = 0;

#pragma unroll 32
    for (int i = 0; i < VLAN_STR_MAX; i++) {
        if ((const void *)(p + i) >= p_end)
            break;
        __u8 c = p[i];
        if (c < '0' || c > '9')
            break;
        val = val * 10 + (__u32)(c - '0');
        digits++;
    }
    if (digits == 0 || val > VLAN_ID_MAX)
        return -1;
    *out = val;
    return 0;
}

/* cerca il primo attributo di tipo 'want'; ritorna il puntatore al valore
 * (NULL se assente) e scrive la lunghezza del valore in *vlen.
 *
 * Niente ciclo unico che accumula i tre attributi: con il dispatch a tre
 * rami il verifier esplora 4 percorsi per iterazione su TUTTE le iterazioni
 * (i rami "trovato" e "non trovato" proseguono entrambe il ciclo) e gli stati
 * esplodono esponenzialmente ("BPF program is too large"). Con una ricerca
 * per tipo e uscita immediata resta un solo percorso vivo per iterazione. */
static inline __attribute__((always_inline)) const __u8 *
find_attr(__u8 *attr, void *rad_end, void *data_end, __u8 want, __u8 *vlen)
{
    for (int i = 0; i < RADIUS_MAX_ATTRS; i++) {
        if ((void *)(attr + 2) > rad_end || (void *)(attr + 2) > data_end)
            return NULL;
        __u8 type = attr[0];
        __u8 alen = attr[1];
        /* TLV malformato: mi fermo */
        if (alen < 2)
            return NULL;
        if ((void *)(attr + alen) > rad_end || (void *)(attr + alen) > data_end)
            return NULL;
        if (type == want) {
            *vlen = alen - 2;
            return attr + 2;
        }
        attr += alen;
    }
    return NULL;
}

SEC("xdp")
int parse_radius(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    /* ogni header va verificato contro data_end prima di accedervi (verifier) */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    /* solo frame IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    /* solo UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    /* IHL minimo: header IP di 20 byte */
    if (ip->ihl < 5)
        return XDP_PASS;

    /* L4 si trova a ip + IHL*4: gestisce anche header IP con opzioni */
    struct udphdr *udp = (struct udphdr *)((char *)ip + (__u32)ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* RADIUS se la porta sorgente o destinazione è 1812/1813 */
    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);
    if (sport != RADIUS_AUTH_PORT && dport != RADIUS_AUTH_PORT &&
        sport != RADIUS_ACCT_PORT && dport != RADIUS_ACCT_PORT)
        return XDP_PASS;

    struct radius_hdr *radius = (void *)(udp + 1);
    if ((void *)(radius + 1) > data_end)
        return XDP_PASS;
    /* analizza solo gli Access-Accept */
    if (radius->code != RADIUS_CODE_ACCESS_ACCEPT)
        return XDP_PASS;

    /* lunghezza dichiarata dal pacchetto: assemblata dai due byte (shift+or su
     * load a byte, sempre bounded per il verifier), senza istruzioni di swap */
    __u16 rad_len = (__u16)(((__u16)radius->length_hi << 8) | radius->length_lo);
    if (rad_len < RADIUS_HDR_LEN)
        return XDP_PASS;
    /* cap esplicito (RFC 2865): oltre a scartare pacchetti patologici, dà al
     * verifier un umax noto sul registro — su alcuni kernel l'OR di due load
     * perde il bound superiore e blocca l'aritmetica "puntatore + scalare" */
    if (rad_len > RADIUS_MAX_PACKET)
        return XDP_PASS;

    /* limite degli attributi, clamped al pacchetto reale (padding/troncamento) */
    void *rad_end = (char *)radius + rad_len;
    if (rad_end > data_end)
        rad_end = data_end;

    /* gli attributi partono subito dopo i 20 byte di header */
    __u8 *attr = (void *)(radius + 1);

    /* ricerche separate con uscita immediata: un passaggio per attributo.
     * Il fallback sull'attr 1 parte solo se manca l'attr 31. */
    __u8 csi_len = 0;
    __u8 user_len = 0;
    __u8 vlan_len = 0;
    const __u8 *csi_val = find_attr(attr, rad_end, data_end,
                                    RADIUS_ATTR_CALLING_STATION_ID, &csi_len);
    const __u8 *vlan_val = find_attr(attr, rad_end, data_end,
                                     RADIUS_ATTR_TUNNEL_PRIVATE_GROUP, &vlan_len);
    const __u8 *user_val = NULL;
    if (!csi_val)
        user_val = find_attr(attr, rad_end, data_end,
                             RADIUS_ATTR_USER_NAME, &user_len);

    /* senza VLAN non c'è niente da registrare */
    if (!vlan_val || !vlan_len)
        return XDP_PASS;

    /* leggibilità con offset COSTANTE: sommare uno scalare runtime al puntatore
     * pkt ne cambia il reg id e il verifier non promuoverebbe il range leggibile
     * del puntatore originale (serve a parse_vlan_id per i load a p+i, i<4) */
    if ((void *)(vlan_val + VLAN_STR_MAX) > data_end)
        return XDP_PASS;

    /* MAC: preferenza all'attr 31, fallback sull'attr 1 se contiene un MAC */
    const __u8 *mac_src = NULL;

    if (csi_val && csi_len >= 2 * MAC_ALEN) {
        if ((void *)(csi_val + MAC_STR_LEN) > data_end)
            return XDP_PASS;
        mac_src = csi_val;
    } else if (user_val && user_len >= 2 * MAC_ALEN) {
        if ((void *)(user_val + MAC_STR_LEN) > data_end)
            return XDP_PASS;
        mac_src = user_val;
    }

    /* senza un MAC riconoscibile non posso comporre la chiave della mappa */
    if (!mac_src)
        return XDP_PASS;

    struct mac_key key = {};
    /* testo del MAC -> 6 byte */
    if (parse_mac(mac_src, &key) < 0)
        return XDP_PASS;

    __u32 vlan = 0;
    if (parse_vlan_id(vlan_val, (const void *)vlan_val + vlan_len, &vlan) < 0)
        return XDP_PASS;

    struct auth_info info = {};
    info.vlan_id = vlan;
    __builtin_memcpy(info.mac_addr, key.addr, MAC_ALEN);
    info.status = 1;

    /* insert-or-update: una re-auth aggiorna la voce esistente */
    bpf_map_update_elem(&auth_map, &key, &info, BPF_ANY);

    /* il traffico passa sempre: l'XDP è solo osservatore */
    return XDP_PASS;
}
