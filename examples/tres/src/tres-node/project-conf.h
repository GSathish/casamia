#ifndef __PROJECT_TRES_EXAMPLE_CONF_H__
#define __PROJECT_TRES_EXAMPLE_CONF_H__

#include "common-conf.h"
#include "casamia-test-conf.h"

/******************************************************************************/
/*                       Casa Mia example 6LoWPAN settings                       */
/******************************************************************************/

#undef UIP_CONF_LOGGING
#define UIP_CONF_LOGGING 0

/* Save some memory for the sky platform. */
#undef UIP_CONF_DS6_NBR_NBU
#define UIP_CONF_DS6_NBR_NBU     5
#undef UIP_CONF_DS6_ROUTE_NBU
#define UIP_CONF_DS6_ROUTE_NBU   5

#endif /* __PROJECT_TRES_EXAMPLE_CONF_H__ */
