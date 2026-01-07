#ifndef __CLASS_GENAI_THREAD_H
#define __CLASS_GENAI_THREAD_H

#include "proxysql.h"

#define GENAI_THREAD_VERSION "0.0.1"

/**
 * @brief GenAI Threads Handler class for managing GenAI module configuration
 *
 * This class handles the GenAI module's configuration variables and lifecycle.
 * It provides methods for initializing, shutting down, and managing module
 * variables that are accessible via the admin interface.
 */
class GenAI_Threads_Handler
{
private:
	int shutdown_;
	pthread_rwlock_t rwlock;

public:
	/**
	 * @brief Structure holding GenAI module configuration variables
	 *
	 * These variables are stored in the global_variables table with the
	 * 'genai-' prefix and can be modified at runtime.
	 */
	struct {
		char* var1;  ///< Dummy variable 1 (string)
		int var2;    ///< Dummy variable 2 (integer)
	} variables;

	struct {
		int threads_initialized = 0;
	} status_variables;

	unsigned int num_threads;

	/**
	 * @brief Default constructor for GenAI_Threads_Handler
	 *
	 * Initializes member variables to default values and sets up
	 * synchronization primitives.
	 */
	GenAI_Threads_Handler();

	/**
	 * @brief Destructor for GenAI_Threads_Handler
	 *
	 * Cleans up allocated resources.
	 */
	~GenAI_Threads_Handler();

	/**
	 * @brief Initialize the GenAI module
	 *
	 * Sets up the module with default configuration values.
	 * Must be called before using any other methods.
	 *
	 * @param num Number of threads to initialize (currently unused, for future expansion)
	 * @param stack Stack size for threads (currently unused, for future expansion)
	 */
	void init(unsigned int num = 0, size_t stack = 0);

	/**
	 * @brief Acquire write lock on variables
	 *
	 * Locks the module for write access to prevent race conditions
	 * when modifying variables.
	 */
	void wrlock();

	/**
	 * @brief Release write lock on variables
	 *
	 * Unlocks the module after write operations are complete.
	 */
	void wrunlock();

	/**
	 * @brief Get the value of a variable as a string
	 *
	 * @param name The name of the variable (without 'genai-' prefix)
	 * @return Dynamically allocated string with the value, or NULL if not found
	 *
	 * @note The caller is responsible for freeing the returned string.
	 */
	char* get_variable(char* name);

	/**
	 * @brief Set the value of a variable
	 *
	 * @param name The name of the variable (without 'genai-' prefix)
	 * @param value The new value to set
	 * @return true if successful, false if variable not found or value invalid
	 */
	bool set_variable(char* name, const char* value);

	/**
	 * @brief Get a list of all variable names
	 *
	 * @return Dynamically allocated array of strings, terminated by NULL
	 *
	 * @note The caller is responsible for freeing the array and its elements.
	 */
	char** get_variables_list();

	/**
	 * @brief Print the version information
	 *
	 * Outputs the GenAI module version to stderr.
	 */
	void print_version();
};

// Global instance of the GenAI Threads Handler
extern GenAI_Threads_Handler *GloGATH;

#endif // __CLASS_GENAI_THREAD_H
