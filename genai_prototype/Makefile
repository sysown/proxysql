# Makefile for GenAI Prototype
# Standalone prototype for testing GenAI module architecture

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
LDFLAGS = -lpthread

# Target executable
TARGET = genai_demo

# Source files
SOURCES = genai_demo.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Default target
all: $(TARGET)

# Link the executable
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $(TARGET)
	@echo "Build complete: $(TARGET)"

# Compile source files
%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Run the demo
run: $(TARGET)
	@echo "Running GenAI demo..."
	./$(TARGET)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean complete"

# Rebuild
rebuild: clean all

# Debug build with more warnings
debug: CXXFLAGS += -DDEBUG -Wpedantic
debug: clean all

# Help target
help:
	@echo "GenAI Prototype Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the demo (default)"
	@echo "  run       - Build and run the demo"
	@echo "  clean     - Remove build artifacts"
	@echo "  rebuild   - Clean and build"
	@echo "  debug     - Build with debug flags and extra warnings"
	@echo "  help      - Show this help message"

.PHONY: all run clean rebuild debug help
