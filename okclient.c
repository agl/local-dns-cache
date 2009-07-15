#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "ip4.h"
#include "okclient.h"

static char fn[3 + IP4_FMT];

int okclient(char ip[4])
{
  return ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1;
}
