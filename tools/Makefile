IDIR := -I../deps/json/json/include

eventslog_reader_sample: eventslog_reader_sample.cpp
	$(CXX) -ggdb -o eventslog_reader_sample eventslog_reader_sample.cpp

# Build target for eventlog_reader_to_json
eventlog_reader_to_json: eventlog_reader_to_json.cpp
	$(CXX) -std=c++17 -ggdb -o $@ $<  $(IDIR)

.PHONY: clean
clean:
	rm -f eventlog_reader_to_json eventslog_reader_sample
