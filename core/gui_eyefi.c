
#include <stdlib.h>
#include "conf.h"
#include "modules.h"
#include "keyboard.h"
#include "platform.h"
#include "gui_lang.h"
#include "gui_draw.h"
#include "gui_menu.h"
#include "gui_mbox.h"

#include "eyefi.h"
#include "gui_eyefi.h"

static Eyefi_transfer_mode_t eyefi_transfer_mode;
static int eyefi_wlan_disabled;
//static int eyefi_direct_priority;
//static int eyefi_direct_before;
//static int eyefi_direct_after;

/* ---------------------------------------------------------- */
// Eyefi add network menu

#define HEAD_LINES              1
#define BODY_LINES              10
#define FOOT_LINES              1
#define HEAD_FONT_LINES         HEAD_LINES * FONT_HEIGHT
#define BODY_FONT_LINES         BODY_LINES * FONT_HEIGHT
#define FOOT_FONT_LINES         FOOT_LINES * FONT_HEIGHT

void gui_eyefi_kbd_process();
void gui_eyefi_draw(int enforce_redraw);

gui_handler GUI_MODE_EYEFI_SELECT_NETWORK =
  { GUI_MODE_MODULE, gui_eyefi_draw, gui_eyefi_kbd_process, gui_eyefi_kbd_process, 0, GUI_MODE_MAGICNUM };

static gui_handler *gui_eyefi_mode_old;

void gui_eyefi_select_network_init()
{
    gui_eyefi_mode_old = gui_set_mode(&GUI_MODE_EYEFI_SELECT_NETWORK);
}

static int gui_eyefi_redraw = 0;

void eyefi_goto_prev(int num)
{

}

void eyefi_goto_next(int num)
{

}

void gui_eyefi_kbd_process()
{
    switch (kbd_get_autoclicked_key() | get_jogdial_direction()) {
        case JOGDIAL_LEFT:
        case KEY_UP:
            eyefi_goto_prev(1);
            gui_eyefi_redraw = 1;
            break;
        case KEY_DOWN:
        case JOGDIAL_RIGHT:
            eyefi_goto_next(1);
            gui_eyefi_redraw = 1;
            break;
        case KEY_ZOOM_OUT:
            eyefi_goto_prev(BODY_LINES-1);
            gui_eyefi_redraw = 1;
            break;
        case KEY_ZOOM_IN:
            eyefi_goto_next(BODY_LINES-1);
            gui_eyefi_redraw = 1;
            break;
        case KEY_RIGHT:
            break;
        case KEY_LEFT:
            break;
        case KEY_SET:
            break;
        case KEY_ERASE:
        case KEY_DISPLAY:
            break;
        case KEY_MENU:
            gui_set_mode(gui_eyefi_mode_old);
            draw_restore();
            break;
    }

}

void gui_eyefi_draw(int enforce_redraw)
{

}

/* ---------------------------------------------------------- */
// Eyefi Menu

static char *eyefi_temp_buffer = NULL;

void eyefi_mbox_select(unsigned int btn)
{
    draw_restore();

    if (eyefi_temp_buffer != NULL)
    {
        free(eyefi_temp_buffer);
        eyefi_temp_buffer = NULL;
    }
}

void eyefi_show_card_info(int arg) {
    if (eyefi_temp_buffer == NULL)
    {
        eyefi_temp_buffer = malloc(256);
        if (eyefi_temp_buffer != NULL)
        {
            eyefi_read_card_info(eyefi_temp_buffer);
            gui_mbox_init(LANG_MSG_EYEFI_INFO_TITLE, (int)eyefi_temp_buffer, MBOX_TEXT_CENTER, eyefi_mbox_select);
        }
    }
}

void eyefi_show_net_list(int arg) {
    if (eyefi_temp_buffer == NULL)
    {
        eyefi_temp_buffer = malloc(100*32);
        if (eyefi_temp_buffer != NULL)
        {
            eyefi_read_configured_nets(eyefi_temp_buffer);
            gui_mbox_init(LANG_MSG_EYEFI_NET_TITLE, (int)eyefi_temp_buffer, MBOX_TEXT_LEFT, eyefi_mbox_select);
        }
    }
}

void eyefi_scan_for_nets(int arg) {
    if (eyefi_temp_buffer == NULL)
    {
        eyefi_temp_buffer = malloc(100*32);
        if (eyefi_temp_buffer != NULL)
        {
            eyefi_scan_nets(eyefi_temp_buffer);
            gui_mbox_init(LANG_MSG_EYEFI_SCAN_TITLE, (int)eyefi_temp_buffer, MBOX_TEXT_LEFT, eyefi_mbox_select);
        }
    }
}

extern void gui_enum_value_change(int *value, int change, unsigned num_items);

const char* gui_eyefi_transfer_enum(int change, int arg) {
    static const char* modes[] = { "Nothing", "Share", "Transfer" };

    gui_enum_value_change((int*)&eyefi_transfer_mode,change,sizeof(modes)/sizeof(modes[0]));

    if (change != 0)
    {
        eyefi_set_transfer_mode(eyefi_transfer_mode);
    }

    return modes[eyefi_transfer_mode];
}

void gui_eyefi_wlan_change(int arg)
{
    eyefi_wlan_disable(arg);
}

extern CMenu eyefi_submenu;

void gui_eyefi_open_submenu(int arg)
{
    static int first_run = 1;

    if (first_run)
    {
        // retrieve the current status of the eyefi card if we don't already have it

        draw_txt_filled_rect_exp(15, 7, 11, 1, 6, MAKE_COLOR(COLOR_RED, COLOR_WHITE));
        draw_string(15*8, 7*16, "Please Wait", MAKE_COLOR(COLOR_RED, COLOR_WHITE));

        eyefi_transfer_mode = eyefi_get_transfer_mode();
        //TODO: make wlan enable persistent
        eyefi_wlan_disabled = !eyefi_wlan_is_enabled();

        first_run = 0;
    }

    gui_activate_sub_menu(&eyefi_submenu, -1);
}

static char textstring[33];

static void tbox_cb(char* name)
{
}

void gui_eyefi_test_tbox(int arg)
{
    // TODO: check for tbox module and display error message if missing
    if (module_tbox_load())
        module_tbox_load()->textbox_init(LANG_TBOX_EYEFI_NETWORK_TITLE, LANG_TBOX_EYEFI_ENTER_SSID, "", 32, tbox_cb, textstring);
}

static CMenuItem eyefi_submenu_items[] = {
        MENU_ITEM(0x86,LANG_MENU_EYEFI_NET_LIST,        MENUITEM_PROC,          eyefi_show_net_list, 0 ),
        MENU_ITEM(0x86,LANG_MENU_EYEFI_NET_SCAN,        MENUITEM_PROC,          eyefi_scan_for_nets, 0 ),
//        MENU_ITEM(0x5c,LANG_MENU_EYEFI_DISABLE_SHUTDOWN,    MENUITEM_BOOL,          &conf.eyefi_disable_shutdown, 0 ),
//        MENU_ITEM(0x5c,LANG_MENU_EYEFI_DELETE_ON_UPLOAD,    MENUITEM_BOOL,          &conf.eyefi_delete_on_upload, 0 ),
        MENU_ITEM(0x5c,LANG_MENU_EYEFI_WIFI_DISABLE,    MENUITEM_BOOL|MENUITEM_ARG_CALLBACK, &eyefi_wlan_disabled, (int)gui_eyefi_wlan_change ),
        MENU_ITEM(0x5c,LANG_MENU_EYEFI_TRANSFER_MODE,   MENUITEM_ENUM,          gui_eyefi_transfer_enum, 0 ),
        MENU_ITEM(0x5c,LANG_MENU_EYEFI_DIRECT_MODE,     MENUITEM_PROC,          gui_eyefi_test_tbox, 0 ),
//        MENU_ITEM(0x5c,LANG_MENU_EYEFI_DIRECT_MODE,     MENUITEM_BOOL,          &eyefi_direct_priority, 0 ),
//        MENU_ITEM(0x58,LANG_MENU_EYEFI_DIRECT_BEFORE,   MENUITEM_INT|MENUITEM_F_UNSIGNED,  &eyefi_direct_before, 0 ),
//        MENU_ITEM(0x58,LANG_MENU_EYEFI_DIRECT_AFTER,    MENUITEM_INT|MENUITEM_F_UNSIGNED,  &eyefi_direct_after, 0 ),
// Report of bricked cards when directly using this followed by a net scan, so leave unimplemented.
//        MENU_ITEM(0x80,LANG_MENU_EYEFI_DIRECT_START,    MENUITEM_PROC,          eyefi_start_direct_mode, 0 ),
        MENU_ITEM(0x80,LANG_MENU_EYEFI_CARD_INFO,       MENUITEM_PROC,          eyefi_show_card_info, 0 ),
        MENU_ITEM(0x80,LANG_MENU_EYEFI_REBOOT,          MENUITEM_PROC,          eyefi_reboot_card, 0 ),
        MENU_ITEM(0x51,LANG_MENU_BACK,                  MENUITEM_UP, 0, 0 ),
        {0}
};

CMenu eyefi_submenu = {0x33,LANG_MENU_EYEFI_TITLE, NULL, eyefi_submenu_items };

/* ---------------------------------------------------------- */
// Eyefi OSD

void gui_eyefi_draw_icon(coord x, coord y, color c)
{
    draw_string(x, y, "EyeFi", c);
}

#define EYEFI_CHECK_INTERVAL 2000

void gui_osd_draw_eyefi()
{
    static int eyefi_osd_wait = 0;
    static int eyefi_status = 0;
    color osd_color = COLOR_WHITE;

    int time = get_tick_count();
    if (eyefi_osd_wait == 0 || (time - eyefi_osd_wait) >= 0 )
    {
        eyefi_osd_wait = time + EYEFI_CHECK_INTERVAL;
        eyefi_status = eyefi_is_uploading();
    }

    switch (eyefi_status)
    {
    case -1:
        osd_color = COLOR_RED;
        break;
    case 0:
        osd_color = COLOR_BLUE;
        break;
    case 1:
        osd_color = COLOR_GREEN;
        break;
    }

    gui_eyefi_draw_icon(conf.eyefi_pos.x, conf.eyefi_pos.y, osd_color);

//    sprintf(osd_buf,"EYEFI:%d", eyefi_status.upload_completed);
//    sprintf(osd_buf,"EYE:%s", eyefi_status.filename);
//    draw_string(conf.eyefi_pos.x, conf.eyefi_pos.y, osd_buf, osd_color);
}
