#!/bin/bash
#
# Simple verification script for vector features
#

echo "=== Vector Features Verification ==="
echo ""

# Check implementation exists
echo "1. Checking NL2SQL_Converter implementation..."
if grep -q "get_query_embedding" /home/rene/proxysql-vec/lib/NL2SQL_Converter.cpp; then
    echo "   ✓ get_query_embedding() found"
else
    echo "   ✗ get_query_embedding() NOT found"
fi

if grep -q "check_vector_cache" /home/rene/proxysql-vec/lib/NL2SQL_Converter.cpp; then
    echo "   ✓ check_vector_cache() found"
else
    echo "   ✗ check_vector_cache() NOT found"
fi

if grep -q "store_in_vector_cache" /home/rene/proxysql-vec/lib/NL2SQL_Converter.cpp; then
    echo "   ✓ store_in_vector_cache() found"
else
    echo "   ✗ store_in_vector_cache() NOT found"
fi

echo ""
echo "2. Checking Anomaly_Detector implementation..."
if grep -q "add_threat_pattern" /home/rene/proxysql-vec/lib/Anomaly_Detector.cpp; then
    # Check if it's not a stub
    if grep -q "TODO: Store in database" /home/rene/proxysql-vec/lib/Anomaly_Detector.cpp; then
        echo "   ✗ add_threat_pattern() still stubbed"
    else
        echo "   ✓ add_threat_pattern() implemented"
    fi
else
    echo "   ✗ add_threat_pattern() NOT found"
fi

echo ""
echo "3. Checking for sqlite-vec usage..."
if grep -q "vec_distance_cosine" /home/rene/proxysql-vec/lib/NL2SQL_Converter.cpp; then
    echo "   ✓ NL2SQL uses vec_distance_cosine"
else
    echo "   ✗ NL2SQL does NOT use vec_distance_cosine"
fi

if grep -q "vec_distance_cosine" /home/rene/proxysql-vec/lib/Anomaly_Detector.cpp; then
    echo "   ✓ Anomaly uses vec_distance_cosine"
else
    echo "   ✗ Anomaly does NOT use vec_distance_cosine"
fi

echo ""
echo "4. Checking GenAI integration..."
if grep -q "extern GenAI_Threads_Handler \*GloGATH" /home/rene/proxysql-vec/lib/NL2SQL_Converter.cpp; then
    echo "   ✓ NL2SQL has GenAI extern"
else
    echo "   ✗ NL2SQL missing GenAI extern"
fi

if grep -q "extern GenAI_Threads_Handler \*GloGATH" /home/rene/proxysql-vec/lib/Anomaly_Detector.cpp; then
    echo "   ✓ Anomaly has GenAI extern"
else
    echo "   ✗ Anomaly missing GenAI extern"
fi

echo ""
echo "5. Checking documentation..."
if [ -f /home/rene/proxysql-vec/doc/VECTOR_FEATURES/README.md ]; then
    echo "   ✓ README.md exists ($(wc -l < /home/rene/proxysql-vec/doc/VECTOR_FEATURES/README.md) lines)"
fi
if [ -f /home/rene/proxysql-vec/doc/VECTOR_FEATURES/API.md ]; then
    echo "   ✓ API.md exists ($(wc -l < /home/rene/proxysql-vec/doc/VECTOR_FEATURES/API.md) lines)"
fi
if [ -f /home/rene/proxysql-vec/doc/VECTOR_FEATURES/ARCHITECTURE.md ]; then
    echo "   ✓ ARCHITECTURE.md exists ($(wc -l < /home/rene/proxysql-vec/doc/VECTOR_FEATURES/ARCHITECTURE.md) lines)"
fi
if [ -f /home/rene/proxysql-vec/doc/VECTOR_FEATURES/TESTING.md ]; then
    echo "   ✓ TESTING.md exists ($(wc -l < /home/rene/proxysql-vec/doc/VECTOR_FEATURES/TESTING.md) lines)"
fi

echo ""
echo "=== Verification Complete ==="
