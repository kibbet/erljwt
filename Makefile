PROJECT = erljwt
PROJECT_DESCRIPTION = Erlang JWT processor/token validator
PROJECT_VERSION = 0.1.0
DEPS=jiffy
LOCAL_DEPS=crypto

include $(if $(ERLANG_MK_FILENAME),$(ERLANG_MK_FILENAME),erlang.mk)
