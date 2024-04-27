/*
 * Copyright (c) 2016-2022 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Driver_SPI.h"

#include "SSE310MPS3.h"
#include "cmsis_driver_config.h"
#include "spi_pl022_drv.h"
#include "RTE_Components.h"

#ifndef ARG_UNUSED
#define ARG_UNUSED(arg)  (void)arg
#endif

/* Driver version */
#define ARM_SPI_DRV_VERSION  ARM_DRIVER_VERSION_MAJOR_MINOR(2, 2)

#if (defined (RTE_SPI0) && (RTE_SPI0 == 1)) || \
    (defined (RTE_SPI1) && (RTE_SPI1 == 1)) || \
    (defined (RTE_SPI2) && (RTE_SPI2 == 1)) || \
    (defined (RTE_SPI3) && (RTE_SPI3 == 1)) || \
    (defined (RTE_SPI4) && (RTE_SPI4 == 1))

/* Driver Version */
static const ARM_DRIVER_VERSION DriverVersion = {
    ARM_SPI_API_VERSION,
    ARM_SPI_DRV_VERSION
};

/* Driver Capabilities */
static const ARM_SPI_CAPABILITIES DriverCapabilities = {
    1, /* Simplex Mode (Master and Slave) */
    1, /* TI Synchronous Serial Interface */
    1, /* Microwire Interface */
    0, /* Signal Mode Fault event: \ref ARM_SPI_EVENT_MODE_FAULT */
    0  /* Reserved */
};

static ARM_DRIVER_VERSION ARM_SPI_GetVersion(void)
{
    return DriverVersion;
}


static ARM_SPI_CAPABILITIES ARM_SPI_GetCapabilities(void)
{
    return DriverCapabilities;
}

typedef struct _SPIx_Resources {
    struct spi_pl022_dev_t* dev;     /* SPI device structure */
    uint32_t nbr_items;              /* Number of items transfered */
    ARM_SPI_STATUS status;           /* SPI dev status */
    ARM_SPI_SignalEvent_t cb_event;  /* Callback function for events */
} SPIx_Resources;

static void ARM_SPI_SignalEvent(const SPIx_Resources* spi_dev, uint32_t event)
{
    if (spi_dev->cb_event == NULL) {
        return;
    }

    spi_dev->cb_event (event);
}

static int32_t ARM_SPIx_Initialize(SPIx_Resources* spi_dev)
{
    enum spi_pl022_error_t ret;

    ret = spi_pl022_init(spi_dev->dev, PeripheralClock);

    if(ret != SPI_PL022_ERR_NONE) {
        return ARM_DRIVER_ERROR;
    }

    return ARM_DRIVER_OK;
}

static int32_t ARM_SPIx_Uninitialize(SPIx_Resources* spi_dev)
{
    ARG_UNUSED(spi_dev);

    /* Nothing to be done */
    return ARM_DRIVER_OK;
}

static int32_t ARM_SPIx_PowerControl(SPIx_Resources* spi_dev,
                                     ARM_POWER_STATE state)
{
    ARG_UNUSED(spi_dev);

    switch (state) {
        case ARM_POWER_OFF:
        case ARM_POWER_LOW:
            return ARM_DRIVER_ERROR_UNSUPPORTED;
        case ARM_POWER_FULL:
            /* Nothing to be done. It's already full power*/
            break;
        /* default:  The default is not defined intentionally to force the
         *           compiler to check that all the enumeration values are
         *           covered in the switch.*/
    }

    return ARM_DRIVER_OK;
}

static int32_t ARM_SPIx_Send(SPIx_Resources* spi_dev, const void* data,
                             uint32_t num)
{
    const uint8_t* p_data;
    enum spi_pl022_error_t ret;
    uint32_t word_size = 1; /* In bytes */

    if(spi_dev->dev->data->ctrl_cfg.word_size > 8) {
        word_size = 2;
    }

    if(data == NULL || num == 0) {
        return ARM_DRIVER_ERROR_PARAMETER;
    }

    /* Maximum number of items. The item size is defined by the word
     * size configured. */
    if(num  > (0xFFFFFFFF / word_size)) {
        return ARM_DRIVER_ERROR_PARAMETER;
    }

    spi_dev->nbr_items = 0;
    p_data = data;

    do {
        ret = spi_pl022_write(spi_dev->dev,
                              spi_dev->dev->data->ctrl_cfg.spi_mode, p_data);
        if(ret != ARM_DRIVER_OK) {
            return ARM_DRIVER_ERROR;
        }

        spi_dev->nbr_items++;
        p_data += word_size;
    } while(spi_dev->nbr_items < num);

    return ARM_DRIVER_OK;
}

static int32_t ARM_SPIx_Receive(SPIx_Resources* spi_dev, void* data,
                                uint32_t num)
{
    uint8_t* p_data;
    enum spi_pl022_error_t ret;
    uint32_t word_size = 1; /* In bytes */

    if(spi_dev->dev->data->ctrl_cfg.word_size > 8) {
        word_size = 2;
    }

    if(data == NULL || num == 0) {
        return ARM_DRIVER_ERROR_PARAMETER;
    }

    /* Maximum number of items. The item size is defined by the word
     * size configured. */
    if(num  > (0xFFFFFFFF / word_size)) {
        return ARM_DRIVER_ERROR_PARAMETER;
    }

    spi_dev->nbr_items = 0;
    p_data = data;

    do {
        ret = spi_pl022_read(spi_dev->dev, p_data);
        if(ret != ARM_DRIVER_OK) {
            return ARM_DRIVER_ERROR;
        }

        spi_dev->nbr_items++;
        p_data += word_size;
    } while(spi_dev->nbr_items < num);

    return ARM_DRIVER_OK;
}

static int32_t ARM_SPIx_Transfer(SPIx_Resources* spi_dev, const void* data_out,
                                 void* data_in, uint32_t num)
{
    enum spi_pl022_error_t ret;
    uint32_t rxlen_ptr;
    uint32_t tx_len_ptr;

    if(num == 0) {
        return ARM_DRIVER_OK;
    }

    tx_len_ptr = num;
    rxlen_ptr = num;

    ret = spi_pl022_txrx_blocking(spi_dev->dev, data_out, &tx_len_ptr,
                                      data_in, &rxlen_ptr);

    if(ret != SPI_PL022_ERR_NONE) {
        return ARM_DRIVER_ERROR;
    }

    ARM_SPI_SignalEvent(spi_dev, ARM_SPI_EVENT_TRANSFER_COMPLETE);

    return ARM_DRIVER_OK;
}

static uint32_t ARM_SPIx_GetDataCount(const SPIx_Resources* spi_dev)
{
    return spi_dev->nbr_items;
}

static int32_t ARM_SPIx_Control(SPIx_Resources* spi_dev, uint32_t control,
                                uint32_t arg)
{
    uint32_t format_mode;
    uint32_t options;
    enum spi_pl022_error_t ret;
    uint32_t word_size;
    struct spi_pl022_ctrl_cfg_t spi_cfg;

    ret = spi_pl022_get_ctrl_cfg(spi_dev->dev, &spi_cfg);
    if(ret != SPI_PL022_ERR_NONE) {
        return ARM_DRIVER_ERROR;
    }

    options = control & ARM_SPI_CONTROL_Msk;

    switch(options)
    {
        case ARM_SPI_MODE_MASTER:
            spi_cfg.spi_mode = 0;
            spi_cfg.bit_rate = arg;
            break;
        case ARM_SPI_SET_BUS_SPEED:
            spi_cfg.bit_rate = arg;
            break;
        case ARM_SPI_GET_BUS_SPEED:
            return (int32_t)spi_cfg.bit_rate;
        case ARM_SPI_MODE_INACTIVE:
        case ARM_SPI_MODE_SLAVE:
        case ARM_SPI_MODE_MASTER_SIMPLEX:
        case ARM_SPI_MODE_SLAVE_SIMPLEX:
        case ARM_SPI_SET_DEFAULT_TX_VALUE:
        case ARM_SPI_CONTROL_SS:
        case ARM_SPI_ABORT_TRANSFER:
            return ARM_DRIVER_ERROR_UNSUPPORTED;
        default:
            break;
    }

    word_size = ((control & ARM_SPI_DATA_BITS_Msk) >> ARM_SPI_DATA_BITS_Pos);
    if(word_size > 0 ) {
        if( (word_size >= 4) && (word_size <= 16)) {
            spi_cfg.word_size = (uint8_t)word_size;
        } else {
            return ARM_SPI_ERROR_DATA_BITS;
        }
    }

    format_mode = (options & ARM_SPI_FRAME_FORMAT_Msk);
    if(format_mode > 0) {
        switch(format_mode) {
            case ARM_SPI_CPOL0_CPHA0:
                 spi_cfg.frame_format &= 0x3F;
                 break;
            case ARM_SPI_CPOL0_CPHA1:
                 spi_cfg.frame_format &= 0x3F;
                 spi_cfg.frame_format |= 0x7F;
                 break;
            case ARM_SPI_CPOL1_CPHA0:
                 spi_cfg.frame_format &= 0x3F;
                 spi_cfg.frame_format |= 0xBF;
                 __attribute__((fallthrough));
            case ARM_SPI_CPOL1_CPHA1:
                 spi_cfg.frame_format |= 0xFF;
                 __attribute__((fallthrough));
            case ARM_SPI_TI_SSI:
                 spi_cfg.frame_format &= 0xFC;
                 spi_cfg.frame_format |= SPI_PL022_CFG_FRF_TI;
                 break;
            case ARM_SPI_MICROWIRE:
                 spi_cfg.frame_format &= 0xFC;
                 spi_cfg.frame_format |= SPI_PL022_CFG_FRF_TI;
                 break;
            default:
                 return ARM_SPI_ERROR_FRAME_FORMAT;
        }
    }

    ret = spi_pl022_set_ctrl_cfg(spi_dev->dev, &spi_cfg);

    if(ret != SPI_PL022_ERR_NONE) {
        return ARM_DRIVER_ERROR;
    }

    return ARM_DRIVER_OK;
}

static ARM_SPI_STATUS ARM_SPIx_GetStatus(const SPIx_Resources* spi_dev)
{
    return spi_dev->status;
}

#if (defined (RTE_SPI0) && (RTE_SPI0 == 1))
/* SPI0 Driver wrapper functions */
static SPIx_Resources SPI0_DEV = {
#if (defined (__DOMAIN_NS) && (__DOMAIN_NS == 1))
    .dev = &SPI0_PL022_DEV_NS,
#else
    .dev = &SPI0_PL022_DEV_S,
#endif
    .nbr_items = 0,
    .status = {
        .busy       = 0,
        .data_lost  = 0,
        .mode_fault = 0,
      },
    .cb_event = NULL,
};

static int32_t ARM_SPI0_Initialize(ARM_SPI_SignalEvent_t cb_event)
{
    SPI0_DEV.cb_event = cb_event;

    return (ARM_SPIx_Initialize(&SPI0_DEV));
}

static int32_t ARM_SPI0_Uninitialize(void)
{
    return (ARM_SPIx_Uninitialize(&SPI0_DEV));
}

static int32_t ARM_SPI0_PowerControl(ARM_POWER_STATE state)
{
    return (ARM_SPIx_PowerControl(&SPI0_DEV, state));
}

static int32_t ARM_SPI0_Send(const void* data, uint32_t num)
{
    return ARM_SPIx_Send(&SPI0_DEV, data, num);
}

static int32_t ARM_SPI0_Receive(void* data, uint32_t num)
{
    return ARM_SPIx_Receive(&SPI0_DEV, data, num);
}

static int32_t ARM_SPI0_Transfer(const void* data_out, void* data_in,
                                 uint32_t num)
{
    return ARM_SPIx_Transfer(&SPI0_DEV, data_out, data_in, num);
}
static uint32_t ARM_SPI0_GetDataCount(void)
{
    return (ARM_SPIx_GetDataCount(&SPI0_DEV));
}
static int32_t ARM_SPI0_Control(uint32_t control, uint32_t arg)
{
    return (ARM_SPIx_Control(&SPI0_DEV, control, arg));
}
static ARM_SPI_STATUS ARM_SPI0_GetStatus(void)
{
    return (ARM_SPIx_GetStatus(&SPI0_DEV));
}

/* SPI0 Driver Control Block */
extern ARM_DRIVER_SPI Driver_SPI0;
ARM_DRIVER_SPI Driver_SPI0 = {
    ARM_SPI_GetVersion,
    ARM_SPI_GetCapabilities,
    ARM_SPI0_Initialize,
    ARM_SPI0_Uninitialize,
    ARM_SPI0_PowerControl,
    ARM_SPI0_Send,
    ARM_SPI0_Receive,
    ARM_SPI0_Transfer,
    ARM_SPI0_GetDataCount,
    ARM_SPI0_Control,
    ARM_SPI0_GetStatus
};
#endif


#if (defined (RTE_SPI1) && (RTE_SPI1 == 1))
/* SPI1 Driver wrapper functions */
static SPIx_Resources SPI1_DEV = {
#if (defined (__DOMAIN_NS) && (__DOMAIN_NS == 1))
    .dev = &SPI1_PL022_DEV_NS,
#else
    .dev = &SPI1_PL022_DEV_S,
#endif
    .nbr_items = 0,
    .status = {
        .busy       = 0,
        .data_lost  = 0,
        .mode_fault = 0,
      },
    .cb_event = NULL,
};

static int32_t ARM_SPI1_Initialize(ARM_SPI_SignalEvent_t cb_event)
{
    SPI1_DEV.cb_event = cb_event;

    return (ARM_SPIx_Initialize(&SPI1_DEV));
}

static int32_t ARM_SPI1_Uninitialize(void)
{
    return (ARM_SPIx_Uninitialize(&SPI1_DEV));
}

static int32_t ARM_SPI1_PowerControl(ARM_POWER_STATE state)
{
    return (ARM_SPIx_PowerControl(&SPI1_DEV, state));
}

static int32_t ARM_SPI1_Send(const void* data, uint32_t num)
{
    return ARM_SPIx_Send(&SPI1_DEV, data, num);
}

static int32_t ARM_SPI1_Receive(void* data, uint32_t num)
{
    return ARM_SPIx_Receive(&SPI1_DEV, data, num);
}

static int32_t ARM_SPI1_Transfer(const void* data_out, void* data_in,
                                 uint32_t num)
{
    return ARM_SPIx_Transfer(&SPI1_DEV, data_out, data_in, num);
}
static uint32_t ARM_SPI1_GetDataCount(void)
{
    return (ARM_SPIx_GetDataCount(&SPI1_DEV));
}
static int32_t ARM_SPI1_Control(uint32_t control, uint32_t arg)
{
    return (ARM_SPIx_Control(&SPI1_DEV, control, arg));
}
static ARM_SPI_STATUS ARM_SPI1_GetStatus(void)
{
    return (ARM_SPIx_GetStatus(&SPI1_DEV));
}

/* SPI1 Driver Control Block */
extern ARM_DRIVER_SPI Driver_SPI1;
ARM_DRIVER_SPI Driver_SPI1 = {
    ARM_SPI_GetVersion,
    ARM_SPI_GetCapabilities,
    ARM_SPI1_Initialize,
    ARM_SPI1_Uninitialize,
    ARM_SPI1_PowerControl,
    ARM_SPI1_Send,
    ARM_SPI1_Receive,
    ARM_SPI1_Transfer,
    ARM_SPI1_GetDataCount,
    ARM_SPI1_Control,
    ARM_SPI1_GetStatus
};
#endif

#if (defined (RTE_SPI2) && (RTE_SPI2 == 1))
/* SPI2 Driver wrapper functions */
static SPIx_Resources SPI2_DEV = {
#if (defined (__DOMAIN_NS) && (__DOMAIN_NS == 1))
    .dev = &SPI2_PL022_DEV_NS,
#else
    .dev = &SPI2_PL022_DEV_S,
#endif
    .nbr_items = 0,
    .status = {
        .busy       = 0,
        .data_lost  = 0,
        .mode_fault = 0,
      },
    .cb_event = NULL,
};

static int32_t ARM_SPI2_Initialize(ARM_SPI_SignalEvent_t cb_event)
{
    SPI2_DEV.cb_event = cb_event;

    return (ARM_SPIx_Initialize(&SPI2_DEV));
}

static int32_t ARM_SPI2_Uninitialize(void)
{
    return (ARM_SPIx_Uninitialize(&SPI2_DEV));
}

static int32_t ARM_SPI2_PowerControl(ARM_POWER_STATE state)
{
    return (ARM_SPIx_PowerControl(&SPI2_DEV, state));
}

static int32_t ARM_SPI2_Send(const void* data, uint32_t num)
{
    return ARM_SPIx_Send(&SPI2_DEV, data, num);
}

static int32_t ARM_SPI2_Receive(void* data, uint32_t num)
{
    return ARM_SPIx_Receive(&SPI2_DEV, data, num);
}

static int32_t ARM_SPI2_Transfer(const void* data_out, void* data_in,
                                 uint32_t num)
{
    return ARM_SPIx_Transfer(&SPI2_DEV, data_out, data_in, num);
}
static uint32_t ARM_SPI2_GetDataCount(void)
{
    return (ARM_SPIx_GetDataCount(&SPI2_DEV));
}
static int32_t ARM_SPI2_Control(uint32_t control, uint32_t arg)
{
    return (ARM_SPIx_Control(&SPI2_DEV, control, arg));
}
static ARM_SPI_STATUS ARM_SPI2_GetStatus(void)
{
    return (ARM_SPIx_GetStatus(&SPI2_DEV));
}

/* SPI2 Driver Control Block */
extern ARM_DRIVER_SPI Driver_SPI2;
ARM_DRIVER_SPI Driver_SPI2 = {
    ARM_SPI_GetVersion,
    ARM_SPI_GetCapabilities,
    ARM_SPI2_Initialize,
    ARM_SPI2_Uninitialize,
    ARM_SPI2_PowerControl,
    ARM_SPI2_Send,
    ARM_SPI2_Receive,
    ARM_SPI2_Transfer,
    ARM_SPI2_GetDataCount,
    ARM_SPI2_Control,
    ARM_SPI2_GetStatus
};
#endif

#if (defined (RTE_SPI3) && (RTE_SPI3 == 1))
/* SPI3 Driver wrapper functions */
static SPIx_Resources SPI3_DEV = {
#if (defined (__DOMAIN_NS) && (__DOMAIN_NS == 1))
    .dev = &SPI3_PL022_DEV_NS,
#else
    .dev = &SPI3_PL022_DEV_S,
#endif
    .nbr_items = 0,
    .status = {
        .busy       = 0,
        .data_lost  = 0,
        .mode_fault = 0,
      },
    .cb_event = NULL,
};

static int32_t ARM_SPI3_Initialize(ARM_SPI_SignalEvent_t cb_event)
{
    SPI3_DEV.cb_event = cb_event;

    return (ARM_SPIx_Initialize(&SPI3_DEV));
}

static int32_t ARM_SPI3_Uninitialize(void)
{
    return (ARM_SPIx_Uninitialize(&SPI3_DEV));
}

static int32_t ARM_SPI3_PowerControl(ARM_POWER_STATE state)
{
    return (ARM_SPIx_PowerControl(&SPI3_DEV, state));
}

static int32_t ARM_SPI3_Send(const void* data, uint32_t num)
{
    return ARM_SPIx_Send(&SPI3_DEV, data, num);
}

static int32_t ARM_SPI3_Receive(void* data, uint32_t num)
{
    return ARM_SPIx_Receive(&SPI3_DEV, data, num);
}

static int32_t ARM_SPI3_Transfer(const void* data_out, void* data_in,
                                 uint32_t num)
{
    return ARM_SPIx_Transfer(&SPI3_DEV, data_out, data_in, num);
}
static uint32_t ARM_SPI3_GetDataCount(void)
{
    return (ARM_SPIx_GetDataCount(&SPI3_DEV));
}
static int32_t ARM_SPI3_Control(uint32_t control, uint32_t arg)
{
    return (ARM_SPIx_Control(&SPI3_DEV, control, arg));
}
static ARM_SPI_STATUS ARM_SPI3_GetStatus(void)
{
    return (ARM_SPIx_GetStatus(&SPI3_DEV));
}

/* SPI3 Driver Control Block */
extern ARM_DRIVER_SPI Driver_SPI3;
ARM_DRIVER_SPI Driver_SPI3 = {
    ARM_SPI_GetVersion,
    ARM_SPI_GetCapabilities,
    ARM_SPI3_Initialize,
    ARM_SPI3_Uninitialize,
    ARM_SPI3_PowerControl,
    ARM_SPI3_Send,
    ARM_SPI3_Receive,
    ARM_SPI3_Transfer,
    ARM_SPI3_GetDataCount,
    ARM_SPI3_Control,
    ARM_SPI3_GetStatus
};
#endif

#if (defined (RTE_SPI4) && (RTE_SPI4 == 1))
/* SPI4 Driver wrapper functions */
static SPIx_Resources SPI4_DEV = {
#if (defined (__DOMAIN_NS) && (__DOMAIN_NS == 1))
    .dev = &SPI4_PL022_DEV_NS,
#else
    .dev = &SPI4_PL022_DEV_S,
#endif
    .nbr_items = 0,
    .status = {
        .busy       = 0,
        .data_lost  = 0,
        .mode_fault = 0,
      },
    .cb_event = NULL,
};

static int32_t ARM_SPI4_Initialize(ARM_SPI_SignalEvent_t cb_event)
{
    SPI4_DEV.cb_event = cb_event;

    return (ARM_SPIx_Initialize(&SPI4_DEV));
}

static int32_t ARM_SPI4_Uninitialize(void)
{
    return (ARM_SPIx_Uninitialize(&SPI4_DEV));
}

static int32_t ARM_SPI4_PowerControl(ARM_POWER_STATE state)
{
    return (ARM_SPIx_PowerControl(&SPI4_DEV, state));
}

static int32_t ARM_SPI4_Send(const void* data, uint32_t num)
{
    return ARM_SPIx_Send(&SPI4_DEV, data, num);
}

static int32_t ARM_SPI4_Receive(void* data, uint32_t num)
{
    return ARM_SPIx_Receive(&SPI4_DEV, data, num);
}

static int32_t ARM_SPI4_Transfer(const void* data_out, void* data_in,
                                 uint32_t num)
{
    return ARM_SPIx_Transfer(&SPI4_DEV, data_out, data_in, num);
}
static uint32_t ARM_SPI4_GetDataCount(void)
{
    return (ARM_SPIx_GetDataCount(&SPI4_DEV));
}
static int32_t ARM_SPI4_Control(uint32_t control, uint32_t arg)
{
    return (ARM_SPIx_Control(&SPI4_DEV, control, arg));
}
static ARM_SPI_STATUS ARM_SPI4_GetStatus(void)
{
    return (ARM_SPIx_GetStatus(&SPI4_DEV));
}

/* SPI4 Driver Control Block */
extern ARM_DRIVER_SPI Driver_SPI4;
ARM_DRIVER_SPI Driver_SPI4 = {
    ARM_SPI_GetVersion,
    ARM_SPI_GetCapabilities,
    ARM_SPI4_Initialize,
    ARM_SPI4_Uninitialize,
    ARM_SPI4_PowerControl,
    ARM_SPI4_Send,
    ARM_SPI4_Receive,
    ARM_SPI4_Transfer,
    ARM_SPI4_GetDataCount,
    ARM_SPI4_Control,
    ARM_SPI4_GetStatus
};
#endif
#endif
