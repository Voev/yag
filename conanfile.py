from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps

class YetAnotherGost(ConanFile):
    name = "yag"
    version = "0.0.1"
    package_type = "library"

    # Metadata
    author = "Kirill Voyevodin (voev.kirill@gmail.com)"
    description = "Yet another OpenSSL GOST provider"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    options = {
        "shared": [True, False],
        "enable_unit": [True, False],
        "enable_kat": [True, False],
    }

    default_options = {
        "shared": True,
        "enable_unit": False,
        "enable_kat": False
    }

    def requirements(self):
        self.requires("openssl/3.0.14", headers=True, libs=True, run=True)
        self.requires("zlib/1.3.1")
        if self.options.enable_unit or self.options.enable_kat:
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
        if self.options.enable_unit:
            cmake_vars["ENABLE_UNIT"] = "ON"
        if self.options.enable_kat:
            cmake_vars["ENABLE_KAT"] = "ON"
        cmake.configure(variables=cmake_vars)
        cmake.build()
        if self.options.enable_unit:
            cmake.test()
        if self.options.enable_kat:
            self.run(f"cmake --build . --target run_kat")

