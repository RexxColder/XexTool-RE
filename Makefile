# recomp-tool - Xbox 360 / PS2 Reverse Engineering CLI
# Native Linux build (no Wine, no Python runtime)
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -MMD -MP -Isrc

# Engine sources (XexTool-RE)
ENGINE_SRC := $(filter-out src/main.cpp src/selftest.cpp, $(wildcard src/*.cpp)) \
              $(wildcard src/crypto/*.cpp) $(wildcard src/compress/*.cpp)
# Remove sqlite3.c from ENGINE_SRC (it's C, not C++)
ENGINE_SRC := $(filter-out src/sqlite3.c, $(ENGINE_SRC))

# New modules
NEW_SRC := src/ghidra_detect.cpp src/ghidra_plugins.cpp \
           src/export_rexglue.cpp src/export_ps2recomp.cpp

ALL_SRC := $(ENGINE_SRC) $(NEW_SRC)
ALL_OBJ := $(ALL_SRC:.cpp=.o) src/sqlite3.o

CLI_OBJ := src/main.o $(ALL_OBJ)
DEP     := $(CLI_OBJ:.o=.d)

CLI := recomp-tool

all: $(CLI)

$(CLI): $(CLI_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ -ldl -lpthread

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

src/sqlite3.o: src/sqlite3.c
	gcc -O2 -Wall -DSQLITE_THREADSAFE=0 -c $< -o $@

clean:
	rm -f $(ALL_OBJ) src/main.o src/selftest.o src/sqlite3.o $(DEP) $(CLI)

-include $(DEP)
.PHONY: all clean
