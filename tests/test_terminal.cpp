#include <gtest/gtest.h>
#include "terminal.h"
#include <sstream>
#include <iostream>

class TableTest : public ::testing::Test {
protected:
    std::stringstream captured;
    std::streambuf* old_buf = nullptr;

    void SetUp() override {
        old_buf = std::cout.rdbuf(captured.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(old_buf);
    }
};

TEST_F(TableTest, EmptyHeaders) {
    pwman::print_table({}, {});
    EXPECT_TRUE(captured.str().empty());
}

TEST_F(TableTest, HeadersOnly) {
    pwman::print_table({"Name", "Value"}, {});
    std::string output = captured.str();
    EXPECT_NE(output.find("Name"), std::string::npos);
    EXPECT_NE(output.find("Value"), std::string::npos);
    EXPECT_NE(output.find("+"), std::string::npos);
    EXPECT_NE(output.find("|"), std::string::npos);
}

TEST_F(TableTest, SingleRow) {
    pwman::print_table({"Col1", "Col2"}, {{"A", "B"}});
    std::string output = captured.str();
    EXPECT_NE(output.find("Col1"), std::string::npos);
    EXPECT_NE(output.find("A"), std::string::npos);
    EXPECT_NE(output.find("B"), std::string::npos);
}

TEST_F(TableTest, MultipleRows) {
    pwman::print_table(
        {"ID", "Name"},
        {{"1", "Alice"}, {"2", "Bob"}, {"3", "Charlie"}}
    );
    std::string output = captured.str();
    EXPECT_NE(output.find("Alice"), std::string::npos);
    EXPECT_NE(output.find("Bob"), std::string::npos);
    EXPECT_NE(output.find("Charlie"), std::string::npos);
}

TEST_F(TableTest, ColumnWidthAdjusts) {
    pwman::print_table({"X"}, {{"LongValue12345"}});
    std::string output = captured.str();
    EXPECT_NE(output.find("LongValue12345"), std::string::npos);
}

TEST(MessageTest, PrintSuccess) {
    std::stringstream buf;
    auto* old = std::cout.rdbuf(buf.rdbuf());
    pwman::print_success("done");
    std::cout.rdbuf(old);
    EXPECT_NE(buf.str().find("[+]"), std::string::npos);
    EXPECT_NE(buf.str().find("done"), std::string::npos);
}

TEST(MessageTest, PrintError) {
    std::stringstream buf;
    auto* old = std::cerr.rdbuf(buf.rdbuf());
    pwman::print_error("fail");
    std::cerr.rdbuf(old);
    EXPECT_NE(buf.str().find("[!]"), std::string::npos);
    EXPECT_NE(buf.str().find("fail"), std::string::npos);
}

TEST(MessageTest, PrintInfo) {
    std::stringstream buf;
    auto* old = std::cout.rdbuf(buf.rdbuf());
    pwman::print_info("info");
    std::cout.rdbuf(old);
    EXPECT_NE(buf.str().find("[*]"), std::string::npos);
    EXPECT_NE(buf.str().find("info"), std::string::npos);
}
