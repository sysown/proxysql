#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "otel_tracer.h"

using namespace testing;

// Mock exporter for testing
class MockExporter : public otel_exporter::OtlpHttpExporter {
public:
    MockExporter() : created_count_(0), failure_count_(0) {}

    MOCK_METHOD(bool, Export, (const opentelemetry::nostd::span<const otel_trace_api::Span*>& spans), (override));

    static std::unique_ptr<otel_exporter::OtlpHttpExporter> Create(
        const otel_exporter::OtlpHttpExporterOptions& options) {
        auto exporter = std::make_unique<MockExporter>();
        static_cast<MockExporter*>(exporter.get())->options_ = options;
        static_cast<MockExporter*>(exporter.get())->created_count_++;
        return exporter;
    }

    otel_exporter::OtlpHttpExporterOptions options_;
    int created_count_;
    int failure_count_;
};

// Mock processor for testing
class MockProcessor : public otel_trace_sdk::SpanProcessor {
public:
    MockProcessor() : export_success_(true) {}

    MOCK_METHOD(void, OnStart,
                (const otel_trace_api::Span& span,
                 const otel_trace_api::SpanContext& parent_context),
                (override));

    MOCK_METHOD(void, OnEnd,
                (const otel_trace_api::Span& span),
                (override));

    MOCK_METHOD(void, OnForceFlush,
                (std::chrono::microseconds timeout,
                 nostd::function<void(bool)> result_callback),
                (override));

    MOCK_METHOD(void, OnShutdown,
                (std::chrono::microseconds timeout,
                 nostd::function<void(bool)> result_callback),
                (override));

    void set_export_success(bool success) { export_success_ = success; }

    bool export_success_;
};

// Test fixture for OTelTracer tests
class OTelTracerTest : public Test {
protected:
    void SetUp() override {
        tracer_ = std::make_unique<OTelTracer>();
    }

    void TearDown() override {
        tracer_.reset();
    }

    std::unique_ptr<OTelTracer> tracer_;
};

// Test tracer creation and destruction
TEST_F(OTelTracerTest, CreationDestruction) {
    EXPECT_NO_THROW({
        OTelTracer tracer;
    });
}

// Test setting and getting global tracer
TEST_F(OTelTracerTest, GlobalTracer) {
    // Initially should be null
    EXPECT_EQ(OTelTracer::GetGlobalTracer(), nullptr);

    // Set global tracer
    OTelTracer::SetGlobalTracer(tracer_.get());
    EXPECT_EQ(OTelTracer::GetGlobalTracer(), tracer_.get());

    // Set to null
    OTelTracer::SetGlobalTracer(nullptr);
    EXPECT_EQ(OTelTracer::GetGlobalTracer(), nullptr);
}

// Test default configuration values
TEST_F(OTelTracerTest, DefaultConfiguration) {
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_service_name")), "proxysql");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_exporter_otlp_protocol")), "http/protobuf");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_exporter_otlp_endpoint")), "http://127.0.0.1:4318");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_exporter_otlp_compression")), "none");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_exporter_otlp_timeout")), "10000");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_bsp_schedule_delay")), "5000");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_bsp_max_queue_size")), "2048");
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_bsp_max_export_batch_size")), "512");
}

// Test variable setting and getting
TEST_F(OTelTracerTest, VariableManagement) {
    // Test boolean variable
    EXPECT_TRUE(tracer_->SetVariable("trace_enable", "true"));
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_enable")), "true");

    EXPECT_TRUE(tracer_->SetVariable("trace_enable", "false"));
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_enable")), "false");

    // Test string variable
    EXPECT_TRUE(tracer_->SetVariable("trace_service_name", "my_service"));
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_service_name")), "my_service");

    // Test numeric variable
    EXPECT_TRUE(tracer_->SetVariable("trace_exporter_otlp_timeout", "20000"));
    EXPECT_EQ(std::string(tracer_->GetVariable("trace_exporter_otlp_timeout")), "20000");

    // Test invalid values
    EXPECT_FALSE(tracer_->SetVariable("trace_enable", "invalid"));
    EXPECT_FALSE(tracer_->SetVariable("trace_exporter_otlp_timeout", "0"));
    EXPECT_FALSE(tracer_->SetVariable("trace_exporter_otlp_timeout", "-1"));
}

// Test filter management
TEST_F(OTelTracerTest, FilterManagement) {
    std::set<std::string> filters;

    // Test empty filter
    filters = tracer_->GetFilter();
    EXPECT_TRUE(filters.empty());

    // Test setting filter
    filters.insert("file1.cpp:123:func1");
    tracer_->SetFilter(filters);

    std::set<std::string> retrieved_filters = tracer_->GetFilter();
    EXPECT_EQ(retrieved_filters.size(), 1);
    EXPECT_EQ(*retrieved_filters.begin(), "file1.cpp:123:func1");
}

// Test span filtering functionality
TEST_F(OTelTracerTest, SpanFiltering) {
    // Test without filter
    EXPECT_TRUE(tracer_->allow_span("test.cpp", 42, "test_span"));

    // Set filter that allows this span
    std::set<std::string> filters;
    filters.insert("test.cpp:42:test_span");
    tracer_->SetFilter(filters);

    EXPECT_TRUE(tracer_->allow_span("test.cpp", 42, "test_span"));

    // Test disallowing
    EXPECT_FALSE(tracer_->allow_span("test.cpp", 43, "test_span"));
    EXPECT_FALSE(tracer_->allow_span("other.cpp", 42, "test_span"));
    EXPECT_FALSE(tracer_->allow_span("test.cpp", 42, "other_span"));

    // Test partial matching - file only
    filters.insert("test.cpp:0:");
    tracer_->SetFilter(filters);
    EXPECT_TRUE(tracer_->allow_span("test.cpp", 43, "other_span"));
}

// Test resource attributes parsing
TEST_F(OTelTracerTest, ResourceAttributes) {
    // Test default service name
    auto resource = tracer_->get_resource_attributes();
    EXPECT_TRUE(resource.find("service.name") != resource.end());
    EXPECT_EQ(resource.at("service.name"), "proxysql");

    // Test setting resource attributes
    tracer_->SetVariable("trace_resource_attributes", "attr1=value1,attr2=value2");
    resource = tracer_->get_resource_attributes();

    EXPECT_EQ(resource.at("service.name"), "proxysql");
    EXPECT_EQ(resource.at("attr1"), "value1");
    EXPECT_EQ(resource.at("attr2"), "value2");

    // Test empty attributes
    tracer_->SetVariable("trace_resource_attributes", "");
    resource = tracer_->get_resource_attributes();
    EXPECT_EQ(resource.size(), 1);  // Only service.name
}

// Test OTLP headers parsing
TEST_F(OTelTracerTest, OtlpHeaders) {
    // Test empty headers
    auto headers = tracer_->get_otlp_headers();
    EXPECT_TRUE(headers.empty());

    // Test setting headers
    tracer_->SetVariable("trace_exporter_otlp_headers", "header1=value1,header2=value2");
    headers = tracer_->get_otlp_headers();

    EXPECT_EQ(headers.size(), 2);
    EXPECT_EQ(headers.at("header1"), "value1");
    EXPECT_EQ(headers.at("header2"), "value2");
}

// Test key-value pair parsing
TEST_F(OTelTracerTest, KeyValueParsing) {
    // Test empty string
    auto pairs = tracer_->parse_key_value_pairs("");
    EXPECT_TRUE(pairs.empty());

    // Test single pair
    pairs = tracer_->parse_key_value_pairs("key=value");
    EXPECT_EQ(pairs.size(), 1);
    EXPECT_EQ(pairs[0].first, "key");
    EXPECT_EQ(pairs[0].second, "value");

    // Test multiple pairs
    pairs = tracer_->parse_key_value_pairs("k1=v1,k2=v2,k3=v3");
    EXPECT_EQ(pairs.size(), 3);
    EXPECT_EQ(pairs[0].first, "k1");
    EXPECT_EQ(pairs[0].second, "v1");
    EXPECT_EQ(pairs[1].first, "k2");
    EXPECT_EQ(pairs[1].second, "v2");
    EXPECT_EQ(pairs[2].first, "k3");
    EXPECT_EQ(pairs[2].second, "v3");

    // Test malformed pairs (should be ignored)
    pairs = tracer_->parse_key_value_pairs("good=value,bad,bad2=,good2=value2");
    EXPECT_EQ(pairs.size(), 2);  // Only valid pairs
    EXPECT_EQ(pairs[0].first, "good");
    EXPECT_EQ(pairs[0].second, "value");
    EXPECT_EQ(pairs[1].first, "good2");
    EXPECT_EQ(pairs[1].second, "value2");

    // Test with spaces (should be trimmed)
    pairs = tracer_->parse_key_value_pairs("  key1 = value1  , key2=value2 ");
    EXPECT_EQ(pairs.size(), 2);
    EXPECT_EQ(pairs[0].first, "key1");
    EXPECT_EQ(pairs[0].second, "value1");
    EXPECT_EQ(pairs[1].first, "key2");
    EXPECT_EQ(pairs[1].second, "value2");
}

// Test tracer availability checking
TEST_F(OTelTracerTest, TracerAvailability) {
    // Initially not available
    EXPECT_FALSE(tracer_->IsTracerAvailable());

    // Test with tracing disabled
    tracer_->SetVariable("trace_enable", "false");
    EXPECT_FALSE(tracer_->IsTracerAvailable());

    // Test with tracing enabled but no tracer (simulated)
    tracer_->SetVariable("trace_enable", "true");
    // Note: IsTracerAvailable() checks internal tracer state which is set during Setup()
    // We can't easily test this without calling Setup() and mocking the OTel components
}

// Test variable list
TEST_F(OTelTracerTest, VariableList) {
    const auto& variables = tracer_->GetVariablesList();

    EXPECT_TRUE(!variables.empty());
    EXPECT_TRUE(std::find(variables.begin(), variables.end(), "trace_enable") != variables.end());
    EXPECT_TRUE(std::find(variables.begin(), variables.end(), "trace_service_name") != variables.end());
    EXPECT_TRUE(std::find(variables.begin(), variables.end(), "trace_exporter_otlp_endpoint") != variables.end());
}

// Test setup configuration validation
TEST_F(OTelTracerTest, SetupConfiguration) {
    // Test invalid service name
    tracer_->SetVariable("trace_service_name", "");
    tracer_->SetVariable("trace_enable", "true");

    // Setup should not crash with empty service name
    EXPECT_NO_THROW({
        tracer_->Setup();
    });

    // Test invalid timeout
    tracer_->SetVariable("trace_exporter_otlp_timeout", "0");
    EXPECT_NO_THROW({
        tracer_->Setup();
    });

    // Test invalid queue size
    tracer_->SetVariable("trace_bsp_max_queue_size", "0");
    EXPECT_NO_THROW({
        tracer_->Setup();
    });
}

// Test concurrent access to tracer
TEST_F(OTelTracerTest, ConcurrentAccess) {
    const int num_threads = 10;
    std::vector<std::thread> threads;

    // Test concurrent variable access
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i]() {
            for (int j = 0; j < 100; ++j) {
                tracer_->SetVariable("trace_service_name", "thread_" + std::to_string(i) + "_" + std::to_string(j));
                std::string name = tracer_->GetVariable("trace_service_name");
                EXPECT_FALSE(name.empty());
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

// Test protocol validation
TEST_F(OTelTracerTest, ProtocolValidation) {
    // Test valid protocols
    EXPECT_TRUE(tracer_->SetVariable("trace_exporter_otlp_protocol", "http/protobuf"));
    // EXPECT_TRUE(tracer_->SetVariable("trace_exporter_otlp_protocol", "http/json"));  // Commented out in implementation
    // EXPECT_TRUE(tracer_->SetVariable("trace_exporter_otlp_protocol", "grpc"));     // Commented out in implementation

    // Test invalid protocol
    EXPECT_FALSE(tracer_->SetVariable("trace_exporter_otlp_protocol", "invalid/protocol"));
}

// Test compression validation
TEST_F(OTelTracerTest, CompressionValidation) {
    // Test valid compression algorithms
    EXPECT_TRUE(tracer_->SetVariable("trace_exporter_otlp_compression", "none"));
    EXPECT_TRUE(tracer_->SetVariable("trace_exporter_otlp_compression", "gzip"));

    // Test invalid compression
    EXPECT_FALSE(tracer_->SetVariable("trace_exporter_otlp_compression", "invalid"));
}