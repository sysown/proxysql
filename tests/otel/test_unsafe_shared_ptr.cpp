#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "unsafe_shared_ptr.h"

using namespace testing;

// Test class for leak detection
class TestObject {
public:
    static int instance_count;
    int value;

    TestObject(int v = 0) : value(v) { instance_count++; }
    ~TestObject() { instance_count--; }

    TestObject(const TestObject& other) : value(other.value) { instance_count++; }
    TestObject& operator=(const TestObject& other) {
        if (this != &other) {
            value = other.value;
        }
        return *this;
    }

    TestObject(TestObject&& other) noexcept : value(other.value) { other.value = 0; instance_count++; }
    TestObject& operator=(TestObject&& other) noexcept {
        if (this != &other) {
            value = other.value;
            other.value = 0;
        }
        return *this;
    }

    // Custom deleter for testing
    static void DeleteTestObject(TestObject* obj) {
        delete obj;
    }
};

int TestObject::instance_count = 0;

// Test fixture for unsafe_shared_ptr tests
class UnsafeSharedPtrTest : public Test {
protected:
    void SetUp() override {
        TestObject::instance_count = 0;
    }

    void TearDown() override {
        // Ensure all objects are cleaned up
        EXPECT_EQ(TestObject::instance_count, 0);
    }
};

// Test default constructor
TEST_F(UnsafeSharedPtrTest, DefaultConstructor) {
    unsafe_shared_ptr<TestObject> ptr;
    EXPECT_FALSE(ptr);
    EXPECT_EQ(ptr.get(), nullptr);
    EXPECT_EQ(ptr.use_count(), 0);
}

// Test constructor with raw pointer
TEST_F(UnsafeSharedPtrTest, ConstructorWithRawPointer) {
    {
        unsafe_shared_ptr<TestObject> ptr(new TestObject(42));
        EXPECT_TRUE(ptr);
        EXPECT_NE(ptr.get(), nullptr);
        EXPECT_EQ(ptr->value, 42);
        EXPECT_EQ(ptr.use_count(), 1);
    }
    // Pointer should be deleted when going out of scope
    EXPECT_EQ(TestObject::instance_count, 0);
}

// Test copy constructor
TEST_F(UnsafeSharedPtrTest, CopyConstructor) {
    unsafe_shared_ptr<TestObject> original(new TestObject(42));
    unsafe_shared_ptr<TestObject> copy(original);

    EXPECT_TRUE(copy);
    EXPECT_EQ(copy->value, 42);
    EXPECT_EQ(copy.use_count(), 2);
    EXPECT_EQ(original.use_count(), 2);
    EXPECT_EQ(TestObject::instance_count, 1);
}

// Test move constructor
TEST_F(UnsafeSharedPtrTest, MoveConstructor) {
    unsafe_shared_ptr<TestObject> original(new TestObject(42));
    unsafe_shared_ptr<TestObject> moved = std::move(original);

    EXPECT_TRUE(moved);
    EXPECT_EQ(moved->value, 42);
    EXPECT_EQ(moved.use_count(), 1);
    EXPECT_FALSE(original);  // NOLINT
    EXPECT_EQ(original.get(), nullptr);
    EXPECT_EQ(TestObject::instance_count, 1);
}

// Test copy assignment
TEST_F(UnsafeSharedPtrTest, CopyAssignment) {
    unsafe_shared_ptr<TestObject> ptr1(new TestObject(42));
    unsafe_shared_ptr<TestObject> ptr2;

    ptr2 = ptr1;

    EXPECT_TRUE(ptr2);
    EXPECT_EQ(ptr2->value, 42);
    EXPECT_EQ(ptr2.use_count(), 2);
    EXPECT_EQ(ptr1.use_count(), 2);
    EXPECT_EQ(TestObject::instance_count, 1);
}

// Test move assignment
TEST_F(UnsafeSharedPtrTest, MoveAssignment) {
    unsafe_shared_ptr<TestObject> ptr1(new TestObject(42));
    unsafe_shared_ptr<TestObject> ptr2;

    ptr2 = std::move(ptr1);

    EXPECT_TRUE(ptr2);
    EXPECT_EQ(ptr2->value, 42);
    EXPECT_EQ(ptr2.use_count(), 1);
    EXPECT_FALSE(ptr1);  // NOLINT
    EXPECT_EQ(ptr1.get(), nullptr);
    EXPECT_EQ(TestObject::instance_count, 1);
}

// Test unique method
TEST_F(UnsafeSharedPtrTest, Unique) {
    unsafe_shared_ptr<TestObject> ptr(new TestObject(42));
    EXPECT_TRUE(ptr.unique());

    unsafe_shared_ptr<TestObject> copy(ptr);
    EXPECT_FALSE(ptr.unique());
    EXPECT_FALSE(copy.unique());
}

// Test reset method
TEST_F(UnsafeSharedPtrTest, Reset) {
    unsafe_shared_ptr<TestObject> ptr(new TestObject(42));
    EXPECT_TRUE(ptr);
    EXPECT_EQ(ptr->value, 42);

    ptr.reset();
    EXPECT_FALSE(ptr);
    EXPECT_EQ(ptr.get(), nullptr);

    ptr.reset(new TestObject(100));
    EXPECT_TRUE(ptr);
    EXPECT_EQ(ptr->value, 100);
    EXPECT_EQ(TestObject::instance_count, 1);
}

// Test reset with nullptr
TEST_F(UnsafeSharedPtrTest, ResetWithNullptr) {
    unsafe_shared_ptr<TestObject> ptr(new TestObject(42));
    ptr.reset(nullptr);
    EXPECT_FALSE(ptr);
}

// Test operator bool
TEST_F(UnsafeSharedPtrTest, OperatorBool) {
    unsafe_shared_ptr<TestObject> ptr;
    EXPECT_FALSE(ptr);

    ptr.reset(new TestObject(42));
    EXPECT_TRUE(ptr);
}

// Test operator-> and operator*
TEST_F(UnsafeSharedPtrTest, Operators) {
    unsafe_shared_ptr<TestObject> ptr(new TestObject(42));

    EXPECT_EQ(ptr->value, 42);
    EXPECT_EQ((*ptr).value, 42);
}

// Test self-assignment (should be no-op)
TEST_F(UnsafeSharedPtrTest, SelfAssignment) {
    unsafe_shared_ptr<TestObject> ptr(new TestObject(42));
    ptr = ptr;  // Self-assignment
    EXPECT_TRUE(ptr);
    EXPECT_EQ(ptr->value, 42);
    EXPECT_EQ(ptr.use_count(), 1);
}

// Test exception safety in constructor
TEST_F(UnsafeSharedPtrTest, ExceptionSafety) {
    EXPECT_THROW({
        // This will throw std::bad_alloc if allocation fails
        unsafe_shared_ptr<int> ptr(new int[1000000000]);
    }, std::bad_alloc);
}

// Test cycle breaking (manual)
TEST_F(UnsafeSharedPtrTest, CycleBreaking) {
    struct Node {
        unsafe_shared_ptr<Node> next;
        Node() = default;
    };

    // Create a cycle
    auto node1 = unsafe_shared_ptr<Node>(new Node());
    auto node2 = unsafe_shared_ptr<Node>(new Node());
    node1->next = node2;
    node2->next = node1;  // Cycle created

    // Break the cycle manually
    node1->next.reset();
    node2->next.reset();

    // Now the nodes will be deleted when they go out of scope
    EXPECT_EQ(TestObject::instance_count, 0);
}

// Test performance with many shared pointers
TEST_F(UnsafeSharedPtrTest, Performance) {
    const int count = 1000;
    std::vector<unsafe_shared_ptr<TestObject>> ptrs;

    for (int i = 0; i < count; ++i) {
        ptrs.emplace_back(new TestObject(i));
    }

    // Verify all objects are created
    EXPECT_EQ(TestObject::instance_count, count);

    // Test copying
    std::vector<unsafe_shared_ptr<TestObject>> copies;
    for (const auto& ptr : ptrs) {
        copies.push_back(ptr);
    }

    // Verify reference counts
    for (int i = 0; i < count; ++i) {
        EXPECT_EQ(ptrs[i].use_count(), 2);
        EXPECT_EQ(copies[i].use_count(), 2);
    }

    // Clear copies first
    copies.clear();

    // Verify only original objects remain
    EXPECT_EQ(TestObject::instance_count, count);
}

// Test use_count() edge cases
TEST_F(UnsafeSharedPtrTest, UseCount) {
    unsafe_shared_ptr<TestObject> ptr;
    EXPECT_EQ(ptr.use_count(), 0);

    ptr.reset(new TestObject(42));
    EXPECT_EQ(ptr.use_count(), 1);

    {
        unsafe_shared_ptr<TestObject> copy(ptr);
        EXPECT_EQ(ptr.use_count(), 2);
        EXPECT_EQ(copy.use_count(), 2);
    }

    EXPECT_EQ(ptr.use_count(), 1);
}

// Test template compilation with different types
TEST_F(UnsafeSharedPtrTest, TemplateCompilation) {
    unsafe_shared_ptr<int> int_ptr(new int(42));
    EXPECT_EQ(*int_ptr, 42);

    unsafe_shared_ptr<std::string> str_ptr(new std::string("hello"));
    EXPECT_EQ(*str_ptr, "hello");

    unsafe_shared_ptr<std::vector<int>> vec_ptr(new std::vector<int>{1, 2, 3});
    EXPECT_EQ((*vec_ptr)[0], 1);
    EXPECT_EQ((*vec_ptr)[1], 2);
    EXPECT_EQ((*vec_ptr)[2], 3);
}