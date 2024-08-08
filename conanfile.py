from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps

class YetAnotherGost(ConanFile):
    name = "yag"
    version = "0.0.1"
    package_type = "library"

    # Metadata
    author = "Kirill Voyevodin voev.kirill@gmail.com"
    description = "Yet another OpenSSL GOST provider"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    options = {
        "shared": [True, False],
        "enable_tests": [True, False]
    }

    default_options = {
        "shared": True,
        "enable_tests": True
    }

    def requirements(self):
        self.requires("openssl/3.0.9")
        self.requires("zlib/1.3.1")
        if self.options.enable_tests:
            self.requires("gtest/1.15.0")

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)
    
    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake_vars = {}
        cmake = CMake(self)
        if self.options.enable_tests:
            cmake_vars["ENABLE_TESTS"] = "ON"
        cmake.configure(variables=cmake_vars)
        cmake.build()
        if self.options.enable_tests:
            cmake.test()

