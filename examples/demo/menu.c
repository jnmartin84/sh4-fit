#include "demo.h"

char save_buffer[13312];   /* cold: only the save screen uses it */

COLD_CODE(menu_draw, 2600)
COLD_CODE(menu_input, 1800)
COLD_CODE(menu_options, 1400)
