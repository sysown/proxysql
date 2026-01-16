#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include "otel_span.h"
#include "otel_tracer.h"

using namespace testing;

// Mock tracer for testing
class MockTracer : public otel_trace_api::Tracer {
public:
    MockTracer() : span_count_(0) {}

    MOCK_METHOD(std::shared_ptr<otel_trace_api::Span>, StartSpan,
                (nostd::string_view name,
                 const otel_trace_api::StartSpanOptions& options,
                 const otel_trace_api::ReferenceList& references),
                (override));

    MOCK_METHOD(nostd::shared_ptr<otel_trace_api::Span>, StartSpan,
                (nostd::string_view name,
                 const otel_trace_api::StartSpanOptions& options,
                 const otel_trace_api::ReferenceList& references,
                 const otel_trace_api::InstrumentationLibrary& instrumentation_library),
                (override));

    MOCK_METHOD(void, ForceFlush,
                (std::chrono::microseconds timeout,
                 nostd::function<void(bool)> result_callback),
                (override));

    MOCK_METHOD(void, Close,
                (std::chrono::microseconds timeout,
                 nostd::function<void(bool)> result_callback),
                (override));

    // Helper to get span count
    int GetSpanCount() const { return span_count_; }

private:
    int span_count_;
};

// Test fixture for OTelSpan tests
class OTelSpanTest : public Test {
protected:
    void SetUp() override {
        mock_tracer_ = std::make_shared<MockTracer>();

        // Create a valid span context
        span_context_ = std::make_unique<otel_trace_api::SpanContext>(
            false, false,
            otel_trace_api::SpanContext::TraceId{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
            otel_trace_api::SpanContext::SpanId{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
            0, false
        );
    }

    void TearDown() override {
        mock_tracer_.reset();
        span_context_.reset();
    }

    std::shared_ptr<MockTracer> mock_tracer_;
    std::unique_ptr<otel_trace_api::SpanContext> span_context_;
};

// Test default constructor
TEST_F(OTelSpanTest, DefaultConstructor) {
    OTelSpan span;
    // Default span should be empty
    EXPECT_EQ(span.GetContext(), nullptr);
}

// Test span creation with parent context
TEST_F(OTelSpanTest, CreateSpanWithParent) {
    EXPECT_CALL(*mock_tracer_, StartSpan(_, _, _))
        .WillOnce([](nostd::string_view name, const otel_trace_api::StartSpanOptions& options, const otel_trace_api::ReferenceList&) {
            // Create a mock span
            auto mock_span = std::make_shared<MockSpan>();
            EXPECT_CALL(*mock_span, GetContext())
                .WillOnce([]() {
                    return otel_trace_api::SpanContext(
                        false, false,
                        otel_trace_api::SpanContext::TraceId{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
                        otel_trace_api::SpanContext::SpanId{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
                        0, false
                    );
                });
            return mock_span;
        });

    OTelSpan span(mock_tracer_.get(), "test_span", span_context_.get());
    EXPECT_NE(span.GetContext(), nullptr);
}

// Test span creation without parent context
TEST_F(OTelSpanTest, CreateSpanWithoutParent) {
    EXPECT_CALL(*mock_tracer_, StartSpan(_, _, _))
        .WillOnce([](nostd::string_view name, const otel_trace_api::StartSpanOptions& options, const otel_trace_api::ReferenceList&) {
            // Create a mock span
            auto mock_span = std::make_shared<MockSpan>();
            EXPECT_CALL(*mock_span, GetContext())
                .WillOnce([]() {
                    return otel_trace_api::SpanContext(
                        false, false,
                        otel_trace_api::SpanContext::TraceId{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
                        otel_trace_api::SpanContext::SpanId{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
                        0, false
                    );
                });
            return mock_span;
        });

    OTelSpan span(mock_tracer_.get(), "test_span");
    EXPECT_NE(span.GetContext(), nullptr);
}

// Test span attributes
TEST_F(OTelSpanTest, SetAttribute) {
    EXPECT_CALL(*mock_tracer_, StartSpan(_, _, _))
        .WillOnce([](nostd::string_view name, const otel_trace_api::StartSpanOptions& options, const otel_trace_api::ReferenceList&) {
            auto mock_span = std::make_shared<MockSpan>();
            EXPECT_CALL(*mock_span, SetAttribute(_, _))
                .WillOnce([](nostd::string_view key, otel_common::AttributeValue value) {
                    // Verify the attribute is set
                    EXPECT_EQ(std::string(key), "test.key");
                    // Note: Can't easily verify value type without more complex mocking
                });
            EXPECT_CALL(*mock_span, GetContext())
                .WillOnce([]() {
                    return otel_trace_api::SpanContext(
                        false, false,
                        otel_trace_api::SpanContext::TraceId{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
                        otel_trace_api::SpanContext::SpanId{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
                        0, false
                    );
                });
            return mock_span;
        });

    OTelSpan span(mock_tracer_.get(), "test_span");
    span.SetAttribute("test.key", "test.value");
}

// Test span name update
TEST_F(OTelSpanTest, UpdateName) {
    EXPECT_CALL(*mock_tracer_, StartSpan(_, _, _))
        .WillOnce([](nostd::string_view name, const otel_trace_api::StartSpanOptions& options, const otel_trace_api::ReferenceList&) {
            auto mock_span = std::make_shared<MockSpan>();
            EXPECT_CALL(*mock_span, UpdateName(_))
                .WillOnce([](nostd::string_view new_name) {
                    EXPECT_EQ(std::string(new_name), "updated_name");
                });
            EXPECT_CALL(*mock_span, GetContext())
                .WillOnce([]() {
                    return otel_trace_api::SpanContext(
                        false, false,
                        otel_trace_api::SpanContext::TraceId{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
                        otel_trace_api::SpanContext::SpanId{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
                        0, false
                    );
                });
            return mock_span;
        });

    OTelSpan span(mock_tracer_.get(), "test_span");
    span.UpdateName("updated_name");
}

// Test OTelSpanCtxWrapper RAII functionality
TEST_F(OTelSpanTest, SpanCtxWrapperRAII) {
    // Test default construction
    OTelSpanCtxWrapper wrapper;
    EXPECT_FALSE(wrapper);

    // Test construction with context
    OTelSpanCtxWrapper wrapper2(span_context_.get());
    EXPECT_TRUE(wrapper2);
    EXPECT_EQ(wrapper2.get(), span_context_.get());

    // Test move constructor
    OTelSpanCtxWrapper wrapper3 = std::move(wrapper2);
    EXPECT_TRUE(wrapper3);
    EXPECT_FALSE(wrapper2);  // NOLINT

    // Test move assignment
    OTelSpanCtxWrapper wrapper4;
    wrapper4 = std::move(wrapper3);
    EXPECT_TRUE(wrapper4);
    EXPECT_FALSE(wrapper3);

    // Test release
    OTelSpanCtx* raw_ptr = wrapper4.release();
    EXPECT_TRUE(raw_ptr);
    EXPECT_FALSE(wrapper4);

    // Test reset
    wrapper4.reset(raw_ptr);
    EXPECT_TRUE(wrapper4);
    wrapper4.reset();
    EXPECT_FALSE(wrapper4);
}

// Test exception safety in span creation
TEST_F(OTelSpanTest, ExceptionSafety) {
    // Create a tracer that throws an exception
    auto throwing_tracer = std::make_shared<ThrowingTracer>();

    // This should not leak memory even if tracer throws
    EXPECT_THROW({
        OTelSpan span(throwing_tracer.get(), "failing_span");
    }, std::runtime_error);
}

// Mock span class for testing
class MockSpan : public otel_trace_api::Span {
public:
    MOCK_METHOD(void, SetAttribute, (nostd::string_view key, otel_common::AttributeValue value), (override));
    MOCK_METHOD(void, AddEvent, (nostd::string_view name, common::Timestamp timestamp, const common::Attributes& attributes), (override));
    MOCK_METHOD(void, AddEvent, (nostd::string_view name, const common::Attributes& attributes), (override));
    MOCK_METHOD(void, SetStatus, (StatusCode status, nostd::string_view description), (override));
    MOCK_METHOD(void, SetError, (bool), (override));
    MOCK_METHOD(void, UpdateName, (nostd::string_view name), (override));
    MOCK_METHOD(otel_trace_api::SpanContext, GetContext, (), (const, override));
    MOCK_METHOD(void, End, (const EndSpanOptions& options), (override));
};

// Throwing tracer for exception testing
class ThrowingTracer : public otel_trace_api::Tracer {
public:
    MOCK_METHOD(std::shared_ptr<otel_trace_api::Span>, StartSpan,
                (nostd::string_view name, const otel_trace_api::StartSpanOptions& options, const otel_trace_api::ReferenceList& references),
                (override));

    std::shared_ptr<otel_trace_api::Span> StartSpan(
        nostd::string_view name,
        const otel_trace_api::StartSpanOptions& options,
        const otel_trace_api::ReferenceList& references) override {
        throw std::runtime_error("Mock tracer exception");
    }

    MOCK_METHOD(void, ForceFlush,
                (std::chrono::microseconds timeout, nostd::function<void(bool)> result_callback),
                (override));
    MOCK_METHOD(void, Close,
                (std::chrono::microseconds timeout, nostd::function<void(bool)> result_callback),
                (override));
};