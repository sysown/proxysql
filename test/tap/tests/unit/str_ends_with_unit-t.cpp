#include "tap.h"

#include "../str_ends_with.h"

#include <stdexcept>

int main() {
	plan(8);

	const std::string tail = "T D=1 C Z(I)";   // 12 characters, as pgsql-native_extq_batch-t checks

	// A reply shorter than the suffix: what a broken proxy could send.
	bool threw = false;
	bool result = true;
	try {
		result = ends_with("Z(I) | Z(I)", tail);
	} catch (const std::out_of_range&) {
		threw = true;
	}
	ok(threw == false, "a string shorter than the suffix does not throw");
	ok(result == false, "a string shorter than the suffix does not end with it");
	ok(ends_with("", tail) == false, "an empty string does not end with a suffix");

	ok(ends_with(tail, tail), "a string ends with itself");
	ok(ends_with("1 2 E(22P02) Z(I) | T D=1 C Z(I)", tail), "a longer string ending with the suffix");
	ok(ends_with("1 2 E(22P02) Z(I) | Z(I)", tail) == false, "a longer string ending otherwise");
	ok(ends_with("T D=2 C Z(I)", tail) == false, "a string as long as the suffix but different");
	ok(ends_with("anything", ""), "every string ends with an empty suffix");

	return exit_status();
}
