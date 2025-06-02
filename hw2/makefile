# ==== 基本設定 ====
CXX      ?= g++
CXXFLAGS += -Iinclude -lcapstone   # 已在上一輪範例加入 -Iinclude
LDFLAGS  += -lcapstone
TARGET   ?= sdb

# ==== 自動尋找原始碼 ====
SRC_DIR  := src
BUILD_DIR:= build
SRCS     := $(wildcard $(SRC_DIR)/*.cpp)
OBJS     := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# ==== 預設目標 ====
all: $(TARGET)

# ==== 連結 ====
$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# ==== 編譯，每個 .cpp → build/%.o ====
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ==== 確保 build/ 目錄存在 ====
$(BUILD_DIR):
	@mkdir -p $@

# ==== 清理 ====
clean:
	$(RM) -r $(BUILD_DIR) $(TARGET)

.PHONY: all clean
