FROM debian:bullseye
ENV DEBIAN_FRONTEND=noninteractive

# RUN apt update && apt install -y llvm-14 clang-14 clang cmake flex bison bc libelf-dev libssl-dev

# -----------------------------------------------------------
# Install necessary packages for manual installation
RUN apt-get update && apt-get install -y wget gnupg lsb-release

# Add LLVM repository key
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

# Add LLVM repository
RUN echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" | tee /etc/apt/sources.list.d/llvm.list


# Update package list
RUN apt-get update
# Install llvm-14 and clang-14
RUN apt-get install -y llvm-14 clang-14 clang cmake flex bison bc libelf-dev libssl-dev

ENV PATH="/usr/lib/llvm-14/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/lib/llvm-14/lib:${LD_LIBRARY_PATH}"
ENV CXX=clang++-14
ENV CC=clang-14
# -----------------------------------------------------------
# Copy your files
ADD ktypes.cpp CMakeLists.txt actor_static.config /plugin/

WORKDIR /plugin/
RUN mkdir build && cd build && cmake .. && make

RUN echo "clang-14 -g -fexperimental-new-pass-manager -fpass-plugin=/plugin/build/libktypesPass.so \"\$@\"" > /bin/clang-ktypes && chmod +x /bin/clang-ktypes
CMD make -C /kernel/ -j `nproc` CC=clang-ktypes
