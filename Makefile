# Define directories
SRC_DIR = src
BIN_DIR = cert  # Certs and compiled classes are in the same directory

# Define source files
SRC_FILES = $(wildcard $(SRC_DIR)/*.java)

# Define the Java compiler
JAVAC = javac

# Define classpath to include the cert directory
CLASSPATH = $(BIN_DIR)

# Target to compile Java source files into the cert directory
all: $(BIN_DIR) $(SRC_FILES)
	$(JAVAC) -d $(BIN_DIR) -cp $(CLASSPATH) $(SRC_FILES)

# Create the cert directory if it doesn't exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean up only class files in the cert directory
clean:
	find $(BIN_DIR) -name "*.class" -exec rm -f {} \;
