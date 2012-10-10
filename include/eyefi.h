
#ifndef EYEFI_H_
#define EYEFI_H_

enum eyefi_transfer_mode
{
    AUTO_TRANSFER = 0,
    SELECTIVE_SHARE = 1,
    SELECTIVE_TRANSFER = 2,
};
typedef enum eyefi_transfer_mode Eyefi_transfer_mode_t;

struct eyefi_upload_status
{
    unsigned int upload_total;
    unsigned int upload_completed;
    char filename[32];
};
typedef struct eyefi_upload_status Eyefi_upload_status_t;

extern void eyefi_reboot_card(void);

extern char *eyefi_read_card_info(char *buf);

extern char *eyefi_read_configured_nets(char *buf);
extern char *eyefi_scan_nets(char *buf);
extern void eyefi_add_network(char *essid, char *ascii_password);
extern void eyefi_remove_network(char *essid);
extern char *eyefi_network_test_status(void);
extern char *eyefi_connected_to(char *buf);
extern int eyefi_wlan_disable(int do_disable);
extern int eyefi_wlan_is_enabled(void);

extern Eyefi_transfer_mode_t eyefi_get_transfer_mode(void);
extern void eyefi_set_transfer_mode(Eyefi_transfer_mode_t transfer_mode);

//extern Eyefi_upload_status_t eyefi_status;
//extern void eyefi_update_status();
extern int eyefi_is_uploading();

#endif /* EYEFI_CONTROL_H_ */
