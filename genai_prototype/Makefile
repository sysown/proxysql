# Makefile for GenAI Prototype
# Standalone prototype for testing GenAI module architecture

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -lcurl
CURL_CFLAGS = $(shell curl-config --cflags)
CURL_LDFLAGS = $(shell curl-config --libs)

# Target executables
TARGET_THREAD = genai_demo
TARGET_EVENT = genai_demo_event
TARGETS = $(TARGET_THREAD) $(TARGET_EVENT)

# Source files
SOURCES_THREAD = genai_demo.cpp
SOURCES_EVENT = genai_demo_event.cpp

# Object files
OBJECTS_THREAD = $(SOURCES_THREAD:.cpp=.o)
OBJECTS_EVENT = $(SOURCES_EVENT:.cpp=.o)

# Default target (build both demos)
all: $(TARGETS)

# Individual demo targets
genai_demo: genai_demo.o
	@echo "Linking genai_demo..."
	$(CXX) genai_demo.o $(LDFLAGS) -o genai_demo
	@echo "Build complete: genai_demo"

genai_demo_event: genai_demo_event.o
	@echo "Linking genai_demo_event..."
	$(CXX) genai_demo_event.o $(CURL_LDFLAGS) $(LDFLAGS) -o genai_demo_event
	@echo "Build complete: genai_demo_event"

# Compile source files
genai_demo.o: genai_demo.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

genai_demo_event.o: genai_demo_event.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(CURL_CFLAGS) -c $< -o $@

# Run the demos
run: $(TARGET_THREAD)
	@echo "Running thread-based GenAI demo..."
	./$(TARGET_THREAD)

run-event: $(TARGET_EVENT)
	@echo "Running event-based GenAI demo..."
	./$(TARGET_EVENT)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(OBJECTS_THREAD) $(OBJECTS_EVENT) $(TARGETS)
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
	@echo "  all          - Build both demos (default)"
	@echo "  genai_demo   - Build thread-based demo"
	@echo "  genai_demo_event - Build event-based demo"
	@echo "  run          - Build and run thread-based demo"
	@echo "  run-event    - Build and run event-based demo"
	@echo "  clean        - Remove build artifacts"
	@echo "  rebuild      - Clean and build all"
	@echo "  debug        - Build with debug flags and extra warnings"
	@echo "  help         - Show this help message"

.PHONY: all run run-event clean rebuild debug help
