have_mqtt := $(shell pkg-config --exists libmosquitto && echo yes)
ifeq ($(have_mqtt),yes)
mqtt_inc := $(shell pkg-config --cflags libmosquitto)
mqtt_lib := $(shell pkg-config --libs libmosquitto)
CFLAGS+=	-DHAVE_MQTT
CFLAGS+=	$(mqtt_inc)
endif
ifeq ($(have_mqtt),yes)
LDLIBS+=	$(mqtt_lib)
endif
