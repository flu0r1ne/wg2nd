# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -Werror
CXXFLAGS += -Isrc -std=c++20 -Wno-unused-function

# Release flags
RELEASE_FLAGS = -O3 -lrt

# Debug flags
DEBUGFLAGS = -ggdb -O0

# Linking flags
LDFLAGS = -largon2

# Object files
OBJECTS := wg2sd.o
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
TARGET = wg2sd

# Build rules
all: CXXFLAGS += $(RELEASE_FLAGS)
all: targets

targets: $(TARGET)

tests: $(TEST_TARGETS)

debug: CXXFLAGS += $(DEBUGFLAGS)
debug: OBJ_DIR = $(DEBUG_OBJ_DIR)
debug: tests targets

$(TARGET): $(addprefix $(OBJ_DIR)/, $(OBJECTS))
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TEST_DIR)/%: $(TEST_DIR)/%.cpp $(addprefix $(OBJ_DIR)/, wg2sd.o) | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(OBJ_DIR) $(DEBUG_OBJ_DIR):
	mkdir -p $@

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(DEBUG_OBJ_DIR) $(TARGET) $(TEST_TARGETS)

# Help rule
help:
	@echo "Available targets:"
	@echo "  all (default)   : Build the project"
	@echo "  release         : Build the project with release flags"
	@echo "  tests           : Build the tests"
	@echo "  debug           : Build the project and tests with debug flags"
	@echo "  clean           : Remove all build artifacts"
	@echo "  help            : Display this help message"
