ifeq ($(shell pkg-config --exists libmosquitto && echo yes),yes)
have_mqtt := yes
mqtt_inc := $(shell pkg-config --cflags libmosquitto)
mqtt_lib := $(shell pkg-config --libs libmosquitto)
endif

ifeq ($(have_mqtt),yes)
CFLAGS+=	-DHAVE_MQTT
CFLAGS+=	$(mqtt_inc)
endif
ifeq ($(have_mqtt),yes)
LDLIBS+=	$(mqtt_lib)
endif
