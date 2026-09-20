CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude -finput-charset=UTF-8 -fexec-charset=UTF-8
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -ldl

APP = crypto_rgr
PLUGIN_DIR = plugins

APP_SOURCES = main.cpp src/auth.cpp src/file_utils.cpp src/plugin_loader.cpp src/console.cpp
APP_HEADERS = include/*.h

.PHONY: all plugins clean rebuild

all: $(APP) plugins

$(APP): $(APP_SOURCES) $(APP_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(APP_SOURCES) -o $@ $(LDLIBS)

plugins: $(PLUGIN_DIR)/librsa.so $(PLUGIN_DIR)/libelgamal.so $(PLUGIN_DIR)/libwake.so

$(PLUGIN_DIR)/librsa.so: plugins/rsa.cpp plugins/plugin_common.h include/plugin_api.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fPIC -shared plugins/rsa.cpp -o $@

$(PLUGIN_DIR)/libelgamal.so: plugins/elgamal.cpp plugins/plugin_common.h include/plugin_api.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fPIC -shared plugins/elgamal.cpp -o $@

$(PLUGIN_DIR)/libwake.so: plugins/wake.cpp plugins/plugin_common.h include/plugin_api.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fPIC -shared plugins/wake.cpp -o $@

clean:
	rm -f $(APP)
	rm -f $(PLUGIN_DIR)/*.so $(PLUGIN_DIR)/*.dll

rebuild: clean all
