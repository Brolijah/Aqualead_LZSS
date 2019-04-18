TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c

HEADERS += \
    types.h \
    aqualead_types.h

QMAKE_CXXFLAGS_RELEASE += -O3
