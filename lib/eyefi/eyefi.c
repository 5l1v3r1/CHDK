/*
 * Based off eyefi-config by Dave Hansen
 * http://sr71.net/projects/eyefi/
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include "eyefi.h"

/* -------------------------------------------------------- */

#define EYEFI_BUF_SIZE 16384
#define MAX_PASCAL_STRING_LEN 32
#define PATHNAME_MAX 32

/* -------------------------------------------------------- */

enum eyefi_file {
    RDIR = 0,
    REQC,
    REQM,
    RSPC,
    RSPM,
    STATUS
};

enum card_info_subcommand {
    MAC_ADDRESS   = 1,
    FIRMWARE_INFO = 2,
    CARD_KEY      = 3,
    API_URL       = 4,
    UNKNOWN_5     = 5, // Chris says these are
    UNKNOWN_6     = 6, // checksums
    LOG_LEN       = 7,
    WLAN_DISABLE  = 10, // 1=disable 0=enable, write is 1 byte, read is var_byte
    UPLOAD_PENDING= 11, // {0x1, STATE}
    HOTSPOT_ENABLE= 12, // {0x1, STATE}
    CONNECTED_TO  = 13, // Currently connected Wifi network
    UPLOAD_STATUS = 14, // current uploading file info
    UNKNOWN_15    = 15, // always returns {0x01, 0x1d} as far as I've seen
    TRANSFER_MODE = 17,
    ENDLESS       = 27,
    DIRECT_WAIT_FOR_CONNECTION = 0x24, // 0 == "direct mode off"
    DIRECT_WAIT_AFTER_TRANSFER = 0x25, // set to 60 when direct mode off
    UNKNOWN_ff    = 0xff, // The D90 does this, and it looks to
                  // return a 1-byte response length
                  // followed by a number of 8-byte responses
                  // But I've only ever seen a single response
                  // [000]: 01 04 1d 00 18 56 aa d5 42 00 00 00 00 00 00 00
                  // It could be a consolidates info command like "info for
                  // everything" so the camera makes fewer calls.
};

// TODO: convert this to use lang defines
char *net_test_states[] = {
    "not scanning",
    "locating network",
    "verifying network key",
    "waiting for DHCP",
    "testing connection to Eye-Fi server",
    "success",
};

const char *net_types[] = {
    "none",
    "WEP",
    "WPA",
    "unknown",
    "WPA2",
};

enum net_type {
    NET_UNSECURED,
    NET_WEP,
    NET_WPA,
    NET_WPA2
};

enum net_password_type {
    NET_PASSWORD_ASCII,
    NET_PASSWORD_RAW, /* raw hex bytes */
};


typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

struct __be32 {
    u32 val;
} __attribute__((packed));
typedef struct __be32 be32;

struct card_seq_num {
    u32 seq;
} __attribute__((packed));

struct pascal_string {
    u8 length;
    u8 value[MAX_PASCAL_STRING_LEN+1];
} __attribute__((packed));

struct var_byte_response {
    u8 len;
    u8 bytes[64];
};
#define var_byte_length(x) (sizeof((x)->len) + (x)->len)

struct noarg_request {
    u8 req;
};

struct card_info_req {
    u8 o;
    u8 subcommand;
} __attribute__((packed));

struct card_config_cmd {
    u8 O;
    u8 subcommand;
    union {
        u8 u8_args[0];
        struct var_byte_response arg;
    };
} __attribute__((packed));

struct card_info_rsp_key {
    struct pascal_string key;
};

struct card_firmware_info {
    struct pascal_string info;
};

#define MAC_BYTES 6
struct mac_address {
    u8 length;
    u8 mac[MAC_BYTES];
} __attribute__((packed));

#define WPA_KEY_BYTES 32
struct wpa_key {
    u8 key[WPA_KEY_BYTES];
} __attribute((packed));

#define WEP_40_KEY_BYTES 5
#define WEP_KEY_BYTES 13
struct wep_key {
    u8 key[WEP_KEY_BYTES];
} __attribute((packed));

struct network_key {
    u8 len;
    union {
        struct wpa_key wpa;
        struct wep_key wep;
    };
} __attribute((packed));

#define ESSID_LEN 32
struct scanned_net {
    char essid[ESSID_LEN];
    signed char strength;
    u8 type;
} __attribute__((packed));

struct scanned_net_list {
    u8 nr;
    struct scanned_net nets[100];
} __attribute__((packed));

struct configured_net {
    char essid[ESSID_LEN];
} __attribute__((packed));

struct configured_net_list {
    u8 nr;
    struct configured_net nets[100];
} __attribute__((packed));

struct net_request {
    char req;
    u8 essid_len;
    char essid[ESSID_LEN];
    struct network_key key;
} __attribute((packed));

struct upload_status {
    u8 len;
    be32 http_len;
    be32 http_done;
    u8 string[0]; // contains filename then directory
}  __attribute__((packed));

/* -------------------------------------------------------- */

extern void usleep(int usec);
extern char *locate_eyefi_mount(void);

extern void pbkdf2_sha1(const char *passphrase, const char *ssid, size_t ssid_len, int iterations, u8 *buf, size_t buflen);

int read_from(enum eyefi_file __file);
int write_to(enum eyefi_file __file, void *stuff, int len);

#define write_struct(file, s) write_to((file), s, sizeof(*(s)))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/* -------------------------------------------------------- */

static void *eyefi_buf = NULL;

void *eyefi_response(void)
{
    return eyefi_buf;
}

//TODO: this is chdk specific, move out to eyefi-chdk.c
void init_buffer(void)
{
    if (eyefi_buf == NULL)
    {
        eyefi_buf = (void*)umalloc(EYEFI_BUF_SIZE);
    }
    memset(eyefi_buf, 0, EYEFI_BUF_SIZE);
}

void release_buffer()
{
    if (eyefi_buf != NULL)
    {
        ufree(eyefi_buf);
    }
    eyefi_buf = NULL;
}

/* -------------------------------------------------------- */

char *eyefi_file_name(enum eyefi_file file)
{
    switch (file) {
    case REQC: return "reqc";
    case REQM: return "reqm";
    case RSPC: return "rspc";
    case RSPM: return "rspm";
    case RDIR: return "";
    case STATUS: return "status";
    }

    return NULL;
}

char *eyefi_file_on(enum eyefi_file file, char *mnt)
{
    char *filename = eyefi_file_name(file);
    char *full = malloc(PATHNAME_MAX);

    if (!full)
        return NULL;

    sprintf(&full[0], "%s/EyeFi/%s", mnt, filename);
    return full;
}

static char *eyefi_file(enum eyefi_file file)
{
    return eyefi_file_on(file, locate_eyefi_mount());
}

/* -------------------------------------------------------- */

struct card_seq_num eyefi_seq;

struct card_seq_num read_seq_from(enum eyefi_file file)
{
    struct card_seq_num *ret;
    read_from(file);
    ret = (struct card_seq_num *)eyefi_response();
    return *ret;
}

void inc_seq(void)
{
    eyefi_seq.seq++;
    write_struct(REQC, &eyefi_seq);
}

u32 eyefi_current_seq(void)
{
    return eyefi_seq.seq;
}

/* -------------------------------------------------------- */

int read_from(enum eyefi_file __file)
{
    int ret = 0;
    int fd;
    char *file;

    if (eyefi_buf != NULL)
    {
        file = eyefi_file(__file);
        if (file != NULL)
        {
            fd = open(file, O_RDONLY, 0);
            if (fd >= 0)
            {
                int bytes_read = read(fd, eyefi_buf, EYEFI_BUF_SIZE);

                if (bytes_read > 0)
                {
                    ret = 1;
                }

                close(fd);
            }
            free(file);
        }
    }
    return ret;
}

int write_to(enum eyefi_file __file, void *stuff, int len)
{
    int ret = 0;
    int wrote;
    int fd;
    char *file;

    if (eyefi_buf != NULL)
    {
        file = eyefi_file(__file);

        if (file != NULL)
        {
            if (len == -1)
            {
                len = strlen(stuff);
            }

            memset(eyefi_buf, 0, EYEFI_BUF_SIZE);
            memcpy(eyefi_buf, stuff, len);

            fd = open(file, O_RDWR|O_CREAT, 0600);
            if (fd >= 0)
            {
                ret = write(fd, eyefi_buf, EYEFI_BUF_SIZE);

                close(fd);
            }
            free(file);
        }
    }
    return ret;
}

int wait_for_response(void)
{
    int good_rsp = 0;
    u32 rsp = 0;
    int i, ret = 0;

    inc_seq();

    for (i = 0; i < 50; i++) {
        struct card_seq_num cardseq = read_seq_from(RSPC);
        rsp = cardseq.seq;
        if (rsp == eyefi_current_seq()) {
            good_rsp = 1;
            break;
        }
        // FIXME: timer callback instead?
        usleep(50000);
    }

    if (good_rsp) {
        read_from(RSPM);
        ret = 1;
    }

    return ret;
}

void zero_card_files(void)
{
    memset(eyefi_buf, 0, EYEFI_BUF_SIZE);
    write_to(RSPM, eyefi_buf, EYEFI_BUF_SIZE);

    read_from(REQM);
    read_from(REQC);
    read_from(RSPM);
}

int init_card()
{
    char *mnt, *file;
    int ret = 0;
    int fd = 0;

    if (eyefi_buf == NULL)
    {
        mnt = locate_eyefi_mount();
        if (mnt != NULL)
        {
            // Verify it's an Eyefi card by checking for
            // the existence of one of it's IPC files.
            file = eyefi_file(RSPC);
            if (file != NULL)
            {
                fd = open(file, O_RDONLY, 0);

                if (fd >= 0)
                {
                    // RSPC file exists, initialise card
                    close(fd);

                    init_buffer();
                    zero_card_files();

                    eyefi_seq = read_seq_from(RSPC);
                    if (eyefi_seq.seq == 0)
                    {
                        eyefi_seq.seq = 0x1234;
                    }
                    eyefi_seq.seq++;

                    ret = 1;
                }
            }
        }
    }
    else
    {
        // already initialised
        ret = 1;
    }

    return ret;
}

void release_card()
{
    release_buffer();
}

/* -------------------------------------------------------- */

// ensures that a pascal string value is cstr terminated
void convert_pascal_to_cstr(struct pascal_string *string)
{
    if (string->length <= MAX_PASCAL_STRING_LEN)
    {
        string->value[string->length] = 0;
    }
    else
    {
        string->value[MAX_PASCAL_STRING_LEN] = 0;
    }
}

int convert_cstr_to_pascal(char *dest, const char *src)
{
    char len = strlen(src);

    dest[0] = len;
    strncpy(dest+1, src, len);

    return len+1;
}

static inline u32 swap_bytes(u32 src)
{
        u32 dest = 0;
        dest |= (src & 0xff000000) >> 24;
        dest |= (src & 0x00ff0000) >>  8;
        dest |= (src & 0x0000ff00) <<  8;
        dest |= (src & 0x000000ff) << 24;
        return dest;
}

static inline u32 be32_to_u32(be32 src)
{
    return swap_bytes(src.val);
}

//static inline be32 u32_to_be32(u32 src)
//{
//    be32 ret;
//    ret.val = swap_bytes(src);
//    return ret;
//}

/* -------------------------------------------------------- */

int card_info_cmd(enum card_info_subcommand cmd)
{
    struct card_info_req cir;
    cir.o = 'o';
    cir.subcommand = cmd;

    write_struct(REQM, &cir);

    return wait_for_response();
}

void card_info_cmd_nowait(enum card_info_subcommand cmd)
{
    struct card_info_req cir;
    cir.o = 'o';
    cir.subcommand = cmd;

    write_struct(REQM, &cir);
}

int issue_noarg_command(u8 cmd)
{
    struct noarg_request req;
    req.req = cmd;

    write_struct(REQM, &req);

    return wait_for_response();
}

int card_config_set(enum card_info_subcommand cmd, struct var_byte_response *args)
{
    int len;
    struct card_config_cmd req;

    req.O = 'O';
    req.subcommand = cmd;
    req.arg.len = args->len;

    memcpy(&req.arg.bytes[0], &args->bytes[0], args->len);

    // try to write a sane number of bytes
    len = offsetof(struct card_config_cmd, arg) + var_byte_length(args);

    write_to(REQM, &req, len);
    return wait_for_response();
}

void config_int_set(enum card_info_subcommand subcommand, int set_to)
{
    struct var_byte_response args;

    args.len = 1;
    args.bytes[0] = set_to;

    card_config_set(subcommand, &args);
    wait_for_response();
}

int config_int_get(enum card_info_subcommand subcommand)
{
    struct var_byte_response *rsp;
    card_info_cmd(subcommand);
    rsp = (struct var_byte_response *)eyefi_response();
    return (rsp->bytes[0] & 0xff);
}

/* --------------------------------------------------------- */
// Simple card query commands

struct mac_address fetch_card_mac_address(void)
{
    struct mac_address *mac;

    card_info_cmd(MAC_ADDRESS);
    mac = (struct mac_address *)eyefi_response();

    return *mac;
}

struct card_firmware_info fetch_card_firmware_info(void)
{
    struct card_firmware_info *info;

    card_info_cmd(FIRMWARE_INFO);
    info = (struct card_firmware_info *)eyefi_response();
    convert_pascal_to_cstr(&info->info);

    return *info;
}

struct card_info_rsp_key fetch_card_key(void)
{
    struct card_info_rsp_key *key;

    card_info_cmd(CARD_KEY);
    key = (struct card_info_rsp_key *)eyefi_response();
    convert_pascal_to_cstr(&key->key);

    return *key;
}

/* --------------------------------------------------------- */
// Upload status query command

struct file_upload_state
{
    int status;
    char fileName[100];
};

int query_uploads_batch(const char *path, struct file_upload_state files[], int numFiles)
{
    int ret = 0;
    int pos, i;
    char numBatch = (char)numFiles;
    char *buf = (char*)eyefi_response();

    if (numBatch > 10)
    {
        numBatch = 10;
    }

    // build query packet
    pos = 0;
    buf[pos++] = 'q';
    pos += convert_cstr_to_pascal(&buf[pos], path);
    buf[pos++] = numFiles;
    for (i = 0; i < numBatch; i++)
    {
        pos += convert_cstr_to_pascal(&buf[pos], files[i].fileName);
    }

    write_to(REQM, buf, pos);

    if (wait_for_response())
    {
        for (i = 0; i < numBatch; i++)
        {
            files[i].status = buf[i];
        }
        ret = numBatch;
    }

    return ret;
}

int query_uploads(const char *path, struct file_upload_state files[], int numFiles)
{
    int ret = 0;
    int i, j;
    char *pathFix = path;

    // convert CHDK path to eyefi path
    if (path[0] == 'A' && path[1] == '/')
    {
        pathFix++;
    }

    for (i = 0; i < numFiles;)
    {
        int batchCompleted = query_uploads_batch(pathFix, &files[i], numFiles - i);

        i += batchCompleted;
    }

    return ret;
}

/* --------------------------------------------------------- */
// Network

char *net_test_state_name(u8 state)
{
    int size = ARRAY_SIZE(net_test_states);
    if (state >= size)
    {
        return "unknown";
    }
    return net_test_states[state];
}

const char *net_type_name(u8 type)
{
    int size = ARRAY_SIZE(net_types);
    if (type >= size)
    {
        return "unknown";
    }
    return net_types[type];
}

int atoh(char c)
{
    char lc = tolower(c);
    int ret = -1;
    if ((c >= '0') && (c <= '9'))
    {
        ret = c - '0';
    }
    else
    {
        if ((lc >= 'a') && (lc <= 'z'))
        {
            ret = (lc - 'a') + 10;
        }
    }
    return ret;
}

// Allocates a new string; must be freed after use
char *convert_ascii_to_hex(char *ascii)
{
    int i;
    char *hex = NULL;
    int len = strlen(ascii);

    if (len%2 == 0)
    {
        hex = malloc(len/2+1);
        if (hex)
        {
            for (i=0; i < len; i+=2)
            {
                int high = atoh(ascii[i]);
                int low  = atoh(ascii[i+1]);
                u8 byte = (high<<4 | low);

                if (high < 0 || low < 0)
                {
                    free(hex);
                    hex = NULL;
                    break;
                }

                hex[i/2] = byte;
            }
            hex[len/2] = 0;
        }
    }

    return hex;
}

int make_network_key(struct network_key *key, char *essid, char *pass)
{
    char *hex_pass;
    int pass_len = strlen(pass);
    int ret = 0;

    memset(key, 0, sizeof(*key));

    switch (pass_len)
    {
    case WPA_KEY_BYTES*2:
        {
            // hex WPA
            hex_pass = convert_ascii_to_hex(pass);
            if (hex_pass)
            {
                key->len = pass_len/2;
                memcpy(&key->wpa.key[0], hex_pass, key->len);
                free(hex_pass);
                ret = 1;
            }
            break;
        }
    case WEP_KEY_BYTES*2:
    case WEP_40_KEY_BYTES*2:
        {
            // hex WEP
            hex_pass = convert_ascii_to_hex(pass);
            if (hex_pass)
            {
                key->len = pass_len/2;
                memcpy(&key->wep.key[0], hex_pass, key->len);
                free(hex_pass);
                ret = 1;
            }
            break;
        }
    default:
        {
            // ASCII WPA
            pbkdf2_sha1(pass, essid, strlen(essid), 4096, &key->wpa.key[0], WPA_KEY_BYTES);
            key->len = WPA_KEY_BYTES;
            ret = 1;
            break;
        }
    }
    return ret;
}

int network_action(char cmd, char *essid, char *ascii_password)
{
    struct net_request nr;
    int ret = 0;

    memset(&nr, 0, sizeof(nr));

    nr.req = cmd;
    strcpy(&nr.essid[0], essid);
    nr.essid_len = strlen(essid);

    if (ascii_password != NULL)
    {
        if (make_network_key(&nr.key, essid, ascii_password))
        {
            write_struct(REQM, &nr);
            ret = wait_for_response();
        }
    }

    return ret;
}

struct scanned_net_list *scan_nets(void)
{
    struct scanned_net_list *scanned;

    issue_noarg_command('g');
    scanned = (struct scanned_net_list *)eyefi_response();

    return scanned;
}

struct configured_net_list *fetch_configured_nets(void)
{
    struct configured_net_list *configured;

    issue_noarg_command('l');
    configured = (struct configured_net_list *)eyefi_response();
    return configured;
}

/* --------------------------------------------------------- */
// Status requests

void fetch_transfer_status(void)
{
    struct upload_status *status;

    char *filename;
    char *dir;
    int http_len;
    int http_complete;

    card_info_cmd(UPLOAD_STATUS);
    status = eyefi_response();

    if (status->len > 8)
    {
        http_len = be32_to_u32(status->http_len);
        http_complete = be32_to_u32(status->http_done);
        filename = (char *)&status->string[0];
        dir = filename + strlen(filename) + 1;
    }
}

/* --------------------------------------------------------- */
// Exported functions for external use

char *eyefi_connected_to(char *buf)
{
  struct pascal_string *essid;

  if (init_card())
  {
      card_info_cmd(CONNECTED_TO);

      essid = eyefi_response();
      convert_pascal_to_cstr(essid);

      if (!essid->length) {
          buf[0] = 0;
      }
      else
      {
          strncpy(buf, (const char *)essid->value, essid->length);
      }

      release_card();
  }

  return buf;
}

int eyefi_wlan_disable(int do_disable)
{
    struct card_config_cmd req;
    int ret = 0;

    if (init_card())
    {
        req.O = 'O';
        req.subcommand = WLAN_DISABLE;
        if (do_disable)
        {
            req.u8_args[0] = 1;
            req.u8_args[1] = 1;
        }
        else
        {
            req.u8_args[0] = 0;
            req.u8_args[1] = 0;
        }

        write_to(REQM, &req, offsetof(struct card_config_cmd, u8_args) + 1);
        ret = wait_for_response();

        release_card();
    }

    return ret;
}

int eyefi_wlan_is_enabled(void)
{
    int ret = 0;

    if (init_card())
    {
        ret = config_int_get(WLAN_DISABLE);
        release_card();
    }

    return ret;
}

Eyefi_upload_status_t eyefi_status;

//void eyefi_update_status()
//{
//    static int request_active = 0;
//    static int our_seq = 0;
//    struct upload_status *status;
//
////    sprintf(eyefi_status.filename, "%d:%d", request_active, our_seq);
//
//    if (init_card())
//    {
//        if (request_active == 0)
//        {
//            card_info_cmd_nowait(UPLOAD_STATUS);
//            inc_seq();
//            our_seq = eyefi_current_seq();
//            request_active = 1;
//        }
//        else
//        {
//            struct card_seq_num cardseq = read_seq_from(RSPC);
//            if (cardseq.seq == our_seq)
//            {
//                read_from(RSPM);
//                status = eyefi_response();
//
//                if (status->len == 0)
//                {
//                    // no upload
//                    eyefi_status.upload_total = 0;
//                    eyefi_status.upload_completed = 0;
////                    eyefi_status.filename[0] = 0;
//                    sprintf(eyefi_status.filename, "None");
//                }
//                else if (status->len > 8)
//                {
//                    eyefi_status.upload_total = be32_to_u32(status->http_len);
//                    eyefi_status.upload_completed = be32_to_u32(status->http_done);
////                    strncpy(eyefi_status.filename, (char*)status->string, 32);
//                    sprintf(eyefi_status.filename, "Upload");
//                }
//                request_active = 0;
//            }
//            else if (cardseq.seq > our_seq)
//            {
//                // another request has overwritten ours, have to retry
//                request_active = 0;
//            }
//        }
//
//        release_card();
//    }
//}

// Uses the older "status" api, is deprecated!
// aargh why does this not work anymore

//int eyefi_status_export = 0;

#define NOT_KNOWN -1
#define UPLOADING 1
#define IDLE 0

int eyefi_is_uploading()
{
    int ret = NOT_KNOWN;
    int fd = 0, len = 0;
    char *status = NULL;
    char *file;

    file = eyefi_file(STATUS);
    if (file != NULL)
    {
        status = umalloc(10);
        if (status != NULL)
        {
            *status = 0;
            fd = open(file, O_CREAT | O_RDWR, 0);
            {
                if (fd >= 0)
                {
                    len = read(fd, status, 1);
                    if (len > 0)
                    {
//                        eyefi_status_export = *status;
                        if (*status > 0)
                        {
                            ret = UPLOADING;
                        }
                        else
                        {
                            ret = IDLE;
                        }
                    }
                    else
                    {
                        ret = NOT_KNOWN;
                    }
                    lseek(fd, 0, SEEK_SET);
                    *status = 0;
                    write(fd, status, 1);
                    close(fd);
                }
                else
                {
                    // file does not exist; create and populate it
                    fd = open(file, O_CREAT | O_RDWR, 0600);
                    if (fd >= 0)
                    {
                        write(fd, status, 1);
                        close(fd);
                    }
                }
            }
            ufree(status);
        }
        free(file);
    }

    return ret;
}

void eyefi_add_network(char *essid, char *ascii_password)
{
    if (init_card())
    {
        network_action('a', essid, ascii_password);
        release_card();
    }
}

void eyefi_remove_network(char *essid)
{
    if (init_card())
    {
        network_action('d', essid, NULL);
        release_card();
    }
}

void eyefi_reboot_card(void)
{
    if (init_card())
    {
        issue_noarg_command('b');
        release_card();
    }
}

char *eyefi_network_test_status(void)
{
    char *response, status = 0;

    if (init_card())
    {
        issue_noarg_command('s');
        response = eyefi_response();
        status = *response;

        release_card();
    }

    return net_test_state_name(status);
}

char *eyefi_read_card_info(char *buf)
{
    struct mac_address mac;
    struct card_firmware_info info;
    struct card_info_rsp_key key;

    if (init_card())
    {
        mac = fetch_card_mac_address();
        info = fetch_card_firmware_info();
        key = fetch_card_key();

        sprintf(buf,"MAC:\n%02x:%02x:%02x:%02x:%02x:%02x\nKey:\n%s\nFirmware:\n%s\n", mac.mac[0], mac.mac[1], mac.mac[2], mac.mac[3], mac.mac[4], mac.mac[5], key.key.value, info.info.value );

        release_card();
    }
    else
    {
        sprintf(buf, "Eye-Fi card not detected.\n");
    }

    return buf;
}

char *eyefi_read_configured_nets(char *buf)
{
    struct configured_net_list *nets;
    int i;
    char *buf_cursor = buf;

    if (init_card())
    {
        nets = fetch_configured_nets();

        for (i = 0; i < nets->nr; i++)
        {
            int len;
            len = sprintf(buf_cursor, "%s\n", nets->nets[i].essid);
            buf_cursor += len;
        }

        release_card();
    }
    else
    {
        sprintf(buf, "Eye-Fi card not detected.\n");
    }

    return buf;
}

char *eyefi_scan_nets(char *buf)
{
    struct scanned_net_list *nets;;
    int i;
    char *buf_cursor = buf;

    if (init_card())
    {
        nets = scan_nets();

        for (i = 0; i < nets->nr; i++)
        {
            int len;
            len = sprintf(buf_cursor, "%s (%s,%d)\n", nets->nets[i].essid, net_type_name(nets->nets[i].type), nets->nets[i].strength);
            buf_cursor += len;
        }

        release_card();
    }
    else
    {
        sprintf(buf, "Eye-Fi card not detected.\n");
    }
    return buf;
}

Eyefi_transfer_mode_t eyefi_get_transfer_mode(void)
{
    Eyefi_transfer_mode_t ret = AUTO_TRANSFER;

    if (init_card())
    {
        ret = config_int_get(TRANSFER_MODE);
        release_card();
    }

    return ret;
}

void eyefi_set_transfer_mode(Eyefi_transfer_mode_t transfer_mode)
{
    if (init_card())
    {
        config_int_set(TRANSFER_MODE, transfer_mode);
        release_card();
    }
}

int eyefi_is_direct_mode_enabled(void)
{
    int wait_for_secs = config_int_get(DIRECT_WAIT_FOR_CONNECTION);
    if (wait_for_secs > 0)
        return 1;
    return 0;
}

void eyefi_set_direct_mode(unsigned int wait_for_secs, unsigned int wait_after_secs)
{
    // DIRECT_WAIT_FOR_CONNECTION=0 appears to be the trigger
    // to keep direct mode on and off.  But, no matter what
    // DIRECT_WAIT_AFTER_TRANSFER was set to before the mode
    // is disabled, the official software seems to set it to
    // 60 seconds during a disable operation
    if (wait_for_secs == 0)
    {
        config_int_set(DIRECT_WAIT_FOR_CONNECTION,  0);
        config_int_set(DIRECT_WAIT_AFTER_TRANSFER, 60);
    }
    else
    {
        config_int_set(DIRECT_WAIT_FOR_CONNECTION, wait_for_secs);
        config_int_set(DIRECT_WAIT_AFTER_TRANSFER, wait_after_secs);
    }
}
