ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

ifeq ($(BINDIR),)
	BINDIR := /sbin
endif

# Compiler
CXX = g++
CC = gcc

CFLAGS = -Wall -Wextra -Werror -Wno-unused-function
CFLAGS += -Isrc

# Compiler flags
CXXFLAGS = $(CFLAGS)
CXXFLAGS += -std=c++20

# Release flags
RELEASE_FLAGS = -O3
RELEASE_LDFLAGS = -lrt

# Debug flags
DEBUGFLAGS = -ggdb -O0

# Linking flags
LDFLAGS =

C_OBJECTS := src/crypto/encoding.o
C_OBJECTS += src/crypto/curve25519.o
C_OBJECTS += src/crypto/halfsiphash.o
C_OBJECTS += src/crypto/pubkey.o

# Object files
OBJECTS := wg2nd.o
OBJECTS += main.o

# Source directory
SRC_DIR = src
TEST_DIR = test

TEST_FILES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_TARGETS := $(patsubst $(TEST_DIR)/%.cpp, $(TEST_DIR)/%, $(TEST_FILES))

SRC_FILES := $(patsubst %.o,$(SRC_DIR)/%.cpp,$(OBJECTS))

# Object directory
OBJ_DIR = obj
DEBUG_OBJ_DIR = obj/debug

# Target executable
CMD = wg2nd

# Build rules
all: CXXFLAGS += $(RELEASE_FLAGS)
all: CFLAGS += $(RELEASE_FLAGS)
all: LDFLAGS += $(RELEASE_LDFLAGS)
all: targets

targets: $(CMD)

tests: $(TEST_TARGETS)

debug: CXXFLAGS += $(DEBUGFLAGS)
debug: OBJ_DIR = $(DEBUG_OBJ_DIR)
debug: tests targets

$(CMD): $(addprefix $(OBJ_DIR)/, $(OBJECTS)) $(C_OBJECTS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(C_OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


$(TEST_DIR)/%: $(TEST_DIR)/%.cpp $(addprefix $(OBJ_DIR)/, wg2nd.o) | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(OBJ_DIR) $(DEBUG_OBJ_DIR):
	mkdir -p $@

install:
	mkdir -p $(DESTDIR)$(PREFIX)$(BINDIR)/
	install -m 755 $(CMD) $(DESTDIR)$(PREFIX)$(BINDIR)/

uninstall:
	rm -rf $(DESTDIR)$(PREFIX)$(BINDIR)/$(CMD)

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(DEBUG_OBJ_DIR) $(TARGET) $(TEST_TARGETS) $(C_OBJECTS) $(CMD)

.PHONY: install uninstall all clean targets tests

# Help rule
help:
	@echo "Available targets:"
	@echo "  all (default)   : Build the project"
	@echo "  tests           : Build the tests"
	@echo "  debug           : Build the project and tests with debug flags"
	@echo "  clean           : Remove all build artifacts"
	@echo "  install         : install build executables"
	@echo "  uninstall       : uninstall build executables"
	@echo "  help            : Display this help message"

