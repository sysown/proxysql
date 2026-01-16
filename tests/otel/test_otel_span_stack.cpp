#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "otel_span.h"

using namespace testing;

// Mock span context for testing
class MockSpanContext : public otel_trace_api::SpanContext {
public:
    MockSpanContext() : SpanContext(false, false) {}

    // Override span_id() method to return a predictable value
    SpanContext::SpanId span_id() const noexcept override {
        return test_span_id_;
    }

    void set_span_id(const SpanContext::SpanId& id) {
        test_span_id_ = id;
    }

private:
    SpanContext::SpanId test_span_id_;
};

// Test fixture for OTelSpanStack tests
class OTelSpanStackTest : public Test {
protected:
    void SetUp() override {
        // Create mock span contexts with different IDs
        span1 = std::make_unique<MockSpanContext>();
        span2 = std::make_unique<MockSpanContext>();
        span3 = std::make_unique<MockSpanContext>();

        // Set different span IDs
        span1->set_span_id(SpanContext::SpanId{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11});
        span2->set_span_id(SpanContext::SpanId{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22});
        span3->set_span_id(SpanContext::SpanId{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33});
    }

    void TearDown() override {
        // Clean up
        span1.reset();
        span2.reset();
        span3.reset();
    }

    std::unique_ptr<MockSpanContext> span1;
    std::unique_ptr<MockSpanContext> span2;
    std::unique_ptr<MockSpanContext> span3;
};

// Test that an empty stack returns nullptr
TEST_F(OTelSpanStackTest, EmptyStackReturnsNull) {
    OTelSpanStack stack;
    EXPECT_EQ(stack.GetCurrent(), nullptr);
}

// Test attaching and detaching spans
TEST_F(OTelSpanStackTest, AttachAndDetach) {
    OTelSpanStack stack;

    // Initially empty
    EXPECT_EQ(stack.GetCurrent(), nullptr);

    // Attach first span
    stack.Attach(span1.get());
    EXPECT_EQ(stack.GetCurrent(), span1.get());

    // Attach second span
    stack.Attach(span2.get());
    EXPECT_EQ(stack.GetCurrent(), span2.get());

    // Detach second span (should work)
    stack.Detach(span2.get());
    EXPECT_EQ(stack.GetCurrent(), span1.get());

    // Detach first span (should work)
    stack.Detach(span1.get());
    EXPECT_EQ(stack.GetCurrent(), nullptr);
}

// Test detaching from non-empty stack with wrong order
TEST_F(OTelSpanStackTest, DetachWrongOrder) {
    OTelSpanStack stack;

    // Attach spans in order
    stack.Attach(span1.get());
    stack.Attach(span2.get());
    stack.Attach(span3.get());

    // Verify current
    EXPECT_EQ(stack.GetCurrent(), span3.get());

    // Try to detach middle span (should clear from span3 onwards)
    stack.Detach(span2.get());
    EXPECT_EQ(stack.GetCurrent(), span1.get());

    // Should be able to detach remaining span
    stack.Detach(span1.get());
    EXPECT_EQ(stack.GetCurrent(), nullptr);
}

// Test detaching null span (should not crash)
TEST_F(OTelSpanStackTest, DetachNullSpan) {
    OTelSpanStack stack;

    // Detaching null should not crash
    stack.Detach(nullptr);
    EXPECT_EQ(stack.GetCurrent(), nullptr);

    // Attach a span
    stack.Attach(span1.get());

    // Detaching null should still not crash
    stack.Detach(nullptr);
    EXPECT_EQ(stack.GetCurrent(), span1.get());
}

// Test detaching span not in stack (should not crash)
TEST_F(OTelSpanStackTest, DetachSpanNotInStack) {
    OTelSpanStack stack;

    // Detaching span not in stack should not crash
    stack.Detach(span1.get());
    EXPECT_EQ(stack.GetCurrent(), nullptr);

    // Add a span and try to detach a different one
    stack.Attach(span1.get());
    stack.Detach(span2.get());
    EXPECT_EQ(stack.GetCurrent(), span1.get());

    // Should still be able to detach the actual span
    stack.Detach(span1.get());
    EXPECT_EQ(stack.GetCurrent(), nullptr);
}

// Test contains functionality
TEST_F(OTelSpanStackTest, Contains) {
    OTelSpanStack stack;

    // Empty stack should not contain anything
    EXPECT_FALSE(stack.Contains(span1.get()));

    // Add spans
    stack.Attach(span1.get());
    stack.Attach(span2.get());

    // Should contain added spans
    EXPECT_TRUE(stack.Contains(span1.get()));
    EXPECT_TRUE(stack.Contains(span2.get()));

    // Should not contain span not added
    EXPECT_FALSE(stack.Contains(span3.get()));

    // Remove spans
    stack.Detach(span2.get());
    EXPECT_TRUE(stack.Contains(span1.get()));
    EXPECT_FALSE(stack.Contains(span2.get()));

    stack.Detach(span1.get());
    EXPECT_FALSE(stack.Contains(span1.get()));
}

// Test stack capacity
TEST_F(OTelSpanStackTest, Capacity) {
    // Test custom capacity constructor doesn't crash
    OTelSpanStack stack_custom(16);
    // The capacity test is harder to do without accessing private members,
    // but we can at least verify the stack works
    stack_custom.Attach(span1.get());
    EXPECT_EQ(stack_custom.GetCurrent(), span1.get());
}