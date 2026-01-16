# OpenTelemetry Project Structure

This document describes the organized structure of the OpenTelemetry implementation in ProxySQL.

## 📁 Directory Organization

```
proxysql/
├── otel/                           # Documentation and verification folder
│   ├── README.md                   # Navigation guide for this folder
│   ├── PROJECT_STRUCTURE.md       # This file - directory structure overview
│   ├── CHANGES_OPENTELEMETRY.md    # Detailed technical changes documentation
│   ├── otel_2_fixes_summary.md    # Executive summary of improvements
│   ├── IMPLEMENTATION_READY.md     # Readiness checklist and integration guide
│   └── verify_otel_fixes.sh        # Comprehensive verification script
│
├── include/                        # Header files
│   ├── otel_span.h                # Span and RAII wrapper implementation
│   ├── otel_tracer.h              # Tracer class with dependency injection
│   └── unsafe_shared_ptr.h        # Custom shared pointer with documentation
│
├── lib/                           # Source files
│   └── otel_tracer.cpp            # Tracer implementation with error handling
│
├── tests/                         # Test files
│   └── otel/
│       ├── CMakeLists.txt         # Test build configuration
│       ├── test_otel_span.cpp      # Span and RAII wrapper tests
│       ├── test_otel_span_stack.cpp # Span stack management tests
│       ├── test_otel_tracer.cpp    # Tracer functionality tests
│       └── test_unsafe_shared_ptr.cpp # Custom shared pointer tests
│
├── .gitignore                     # Updated with build artifact rules
└── [other ProxySQL files...]
```

## 🎯 Key Benefits of This Organization

### 1. **Clean Project Root**
- Documentation moved to dedicated `otel/` folder
- Project root contains only source code and essential files
- No clutter from documentation or verification scripts

### 2. **Logical Grouping**
- All OpenTelemetry-related files organized together
- Easy to navigate and find specific components
- Clear separation between documentation and code

### 3. **Documentation Centralization**
- All documentation in one location
- Navigation guide (README.md) for the folder
- Comprehensive coverage from technical to executive summaries

### 4. **Easy Maintenance**
- Verification scripts organized with documentation
- Clear structure for adding future documentation
- Consistent naming conventions

## 📋 File Responsibilities

### Documentation Files
- **`README.md`** - Quick start guide and folder overview
- **`PROJECT_STRUCTURE.md`** - Directory organization explanation
- **`CHANGES_OPENTELEMETRY.md`** - Detailed technical documentation
- **`otel_2_fixes_summary.md`** - Executive summary and highlights
- **`IMPLEMENTATION_READY.md`** - Integration checklist and guide
- **`verify_otel_fixes.sh`** - Automated verification script

### Source Files
- **`include/otel_span.h`** - Span and context management
- **`include/otel_tracer.h`** - Tracer interface and dependency injection
- **`lib/otel_tracer.cpp`** - Tracer implementation with error handling

### Test Files
- **`tests/otel/`** - All OpenTelemetry-related unit tests
- Organized by component for easy maintenance

## 🔧 Usage Patterns

### For Developers
```bash
# Navigate to documentation
cd otel/

# Read overview
cat README.md

# Check implementation readiness
cat IMPLEMENTATION_READY.md

# Run verification
./verify_otel_fixes.sh
```

### For Documentation
```bash
# Technical details
cat CHANGES_OPENTELEMETRY.md

# Executive summary
cat otel_2_fixes_summary.md
```

### For Testing
```bash
# Run specific test component
cd tests/otel && make test_otel_span
```

## 🚀 Integration Guidelines

When integrating with ProxySQL:
1. Review `otel/IMPLEMENTATION_READY.md` for checklist
2. Run `otel/verify_otel_fixes.sh` for validation
3. Consult `otel/CHANGES_OPENTELEMETRY.md` for technical details
4. Use `otel/otel_2_fixes_summary.md` for executive overview

This organization ensures maintainability, clarity, and ease of use while keeping the project root clean and focused on source code.