#ifndef POKUSEW_TERMINAL_H
#define POKUSEW_TERMINAL_H

#define ESC "\033"
// CSI (Control Sequence Introducer) sequences
// see https://en.wikipedia.org/wiki/ANSI_escape_code#CSI_sequences
#define CSI ESC "["
#define CSI_SHOW_CURSOR CSI "?25h"
#define CSI_HIDE_CURSOR CSI "?25l"
#define CSI_CURSOR_POSITION(line, col) CSI line ";" col "H"
#define csp(line, col) CSI_CURSOR_POSITION(line, col)
#define CSI_ERASE_IN_DISPLAY(n) CSI n "J"
#define CSI_ERASE_IN_DISPLAY_ENTIRE_SCREEN CSI_ERASE_IN_DISPLAY("2")
#define CSI_ERASE_IN_LINE(n) CSI n "K"

#define RN "\r\n"
#define RNC CSI_ERASE_IN_LINE("0") "\r\n"

#ifndef nl
#define nl "\r\n"
#endif

// SGR (Select Graphic Rendition) parameters
// see https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_(Select_Graphic_Rendition)_parameters
// multiple arguments can be specified at once, must be separated by semicolon (;)
#define CSI_SGR(attrs) CSI attrs "m"
#define sgr(attrs) sgr(attrs)
#define rst CSI "0m"

#define bold "1"
#define underline "4"

// SGR colors
// see https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
//
//     SGR    description                    notes
//   30–37    Set foreground color
//      38    Set foreground color           Next arguments are 5;n or 2;r;g;b
//      39    Default foreground color       Implementation defined (according to standard)
//   40–47    Set background color
//      48    Set background color           Next arguments are 5;n or 2;r;g;b
//      49    Default background color       Implementation defined (according to standard)
//   90–97    Set bright foreground color    Not in standard
// 100–107    Set bright background color    Not in standard

// 0-7 3-bit colors
// 0 Black
// 1 Red
// 2 Green
// 3 Yellow
// 4 Blue
// 5 Magenta
// 6 Cyan
// 7 White

#define fg_black "30"
#define fg_red "31"
#define fg_green "32"
#define fg_yellow "33"
#define fg_blue "34"
#define fg_magenta "35"
#define fg_cyan "36"
#define fg_white "37"

#define bg_black "40"
#define bg_red "41"
#define bg_green "42"
#define bg_yellow "43"
#define bg_blue "44"
#define bg_magenta "45"
#define bg_cyan "46"
#define bg_white "47"

#define fg_bright_black "90"
#define fg_bright_red "91"
#define fg_bright_green "92"
#define fg_bright_yellow "93"
#define fg_bright_blue "94"
#define fg_bright_magenta "95"
#define fg_bright_cyan "96"
#define fg_bright_white "97"

#define bg_bright_black "100"
#define bg_bright_red "101"
#define bg_bright_green "102"
#define bg_bright_yellow "103"
#define bg_bright_blue "104"
#define bg_bright_magenta "105"
#define bg_bright_cyan "106"
#define bg_bright_white "107"

// simplified usage
// TODO: recursive macros https://stackoverflow.com/questions/12447557/can-we-have-recursive-macros
#define red_s CSI fg_red ";" bold "m"
#define red(text) CSI fg_red ";" bold "m" text rst
#define green_s CSI fg_green ";" bold "m"
#define green(text) CSI fg_green ";" bold "m" text rst
#define yellow_s CSI fg_bright_yellow ";" bold "m"
#define yellow(text) CSI fg_bright_yellow ";" bold "m" text rst
#define blue_s CSI fg_blue ";" bold "m"
#define blue(text) CSI fg_blue ";" bold "m" text rst
#define magenta_s CSI fg_magenta ";" bold "m"
#define magenta(text) CSI fg_magenta ";" bold "m" text rst
#define cyan_s CSI fg_cyan ";" bold "m"
#define cyan(text) CSI fg_cyan ";" bold "m" text rst
#define gray_s CSI fg_bright_black "m"
#define gray(text) CSI fg_bright_black "m" text rst
#define gray_bold_s CSI fg_bright_black ";" bold "m"
#define gray_bold(text) CSI fg_bright_black ";" bold "m" text rst

#endif // POKUSEW_TERMINAL_H
