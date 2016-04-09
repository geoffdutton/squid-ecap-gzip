/*
 *  VIGOS eCAP GZIP Adapter
 *  Copyright (C) 2008-2016 Constantin Rack, VIGOS AG, Germany.
 *
 *  http://www.vigos.com/
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *  -----------------------------------------------------------------
 *
 *  This eCAP adapter is based on the eCAP adapter sample,
 *  available under the following license:
 *
 *  Copyright 2008 The Measurement Factory.
 *  All rights reserved.
 *
 *  This Software is licensed under the terms of the eCAP library (libecap),
 *  including warranty disclaimers and liability limitations.
 *
 *  http://www.e-cap.org/
 */

#include "sample.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>
#include <zlib.h>

namespace Adapter { // not required, but adds clarity

using libecap::size_type;

class Service: public libecap::adapter::Service {
    public:
        // About
        virtual std::string uri() const; // unique across all vendors
        virtual std::string tag() const; // changes with version and config
        virtual void describe(std::ostream &os) const; // free-format info

        // Configuration
        virtual void configure(const libecap::Options &cfg);
        virtual void reconfigure(const libecap::Options &cfg);

        // Lifecycle
        virtual void start(); // expect makeXaction() calls
        virtual void stop(); // no more makeXaction() calls until start()
        virtual void retire(); // no more makeXaction() calls

        // Scope (XXX: this may be changed to look at the whole header)
        virtual bool wantsUrl(const char *url) const;

        // Work
        virtual Adapter::Service::MadeXactionPointer makeXaction(libecap::host::Xaction *hostx);

};

class Xaction: public libecap::adapter::Xaction {
    public:
        Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
        virtual ~Xaction();

        // meta-information for the host transaction
        virtual const libecap::Area option(const libecap::Name &name) const;
        virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

        // lifecycle
        virtual void start();
        virtual void stop();

        // adapted body transmission control
        virtual void abDiscard();
        virtual void abMake();
        virtual void abMakeMore();
        virtual void abStopMaking();

        // adapted body content extraction and consumption
        virtual libecap::Area abContent(size_type offset, size_type size);
        virtual void abContentShift(size_type size);

        // virgin body state notification
        virtual void noteVbContentDone(bool atEnd);
        virtual void noteVbContentAvailable();

    protected:
        void stopVb(); // stops receiving vb (if we are receiving it)
        libecap::host::Xaction *lastHostCall(); // clears hostx

    private:
        libecap::shared_ptr<const Service> service; // configuration access
        libecap::host::Xaction *hostx; // Host transaction rep

        typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
        OperationState receivingVb;
        OperationState sendingAb;

        struct GzipContext {
            z_stream       zstream;
            unsigned char* gzipBuffer;
            unsigned int   checksum;
            unsigned int   originalSize;
            unsigned int   compressedSize;
            unsigned int   sendingOffset;
            unsigned int   lastChunkSize;
        } *gzipContext;

        void gzipInitialize();
        void gzipFinalize();

        struct {
            bool responseCacheControlOk;
            bool responseContentEncodingOk;
            bool responseContentRangeOk;
            bool responseContentTypeOk;
            bool requestAcceptEncodingOk;
        } requirements;

        bool requirementsAreMet();
};

static const std::string CfgErrorPrefix =
    "Modifying Adapter: configuration error: ";
} // namespace Adapter

/**
 * Determines if the response can be compressed or not.
 */
bool Adapter::Xaction::requirementsAreMet() {

    if(!requirements.responseCacheControlOk) {
        return false;
    }

    if(!requirements.responseContentEncodingOk) {
        return false;
    }

    if(!requirements.responseContentRangeOk) {
        return false;
    }

    if(!requirements.responseContentTypeOk) {
        return false;
    }

    if(!requirements.requestAcceptEncodingOk) {
        return false;
    }

    return true;
}

/**
 * Initializes the zlib data structures.
 */
void Adapter::Xaction::gzipInitialize() {
    gzipContext = (struct GzipContext*) malloc(sizeof(struct GzipContext));

    if(gzipContext) {
        // initialize context
        memset(gzipContext, 0, sizeof(struct GzipContext));

        // calculate start CRC32
        gzipContext->checksum = crc32(0,0,0);

        // init zlib's zstream
        const int rc = deflateInit2(&gzipContext->zstream, 9, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);

        switch(rc) {
        case Z_OK:
            // init ok
            break;
        default:
            // TODO: error handling
            break;
        }
    } else {
        // TODO: error handling
    }
}

/**
 * Frees the zlib data structures.
 */
void Adapter::Xaction::gzipFinalize() {
    if(gzipContext) {
        if(gzipContext->gzipBuffer) {
            free(gzipContext->gzipBuffer);
        }
        free(gzipContext);
        gzipContext = 0;
    }
}


std::string Adapter::Service::uri() const {
    return "ecap://www.vigos.com/ecap_gzip";
}

std::string Adapter::Service::tag() const {
    return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const {
    os << "HTTP GZIP compression eCAP adapter";
}

void Adapter::Service::configure(const libecap::Options &cfg) {
    // this service is not configurable
}

void Adapter::Service::reconfigure(const libecap::Options &cfg) {
    // this service is not configurable
}

void Adapter::Service::start() {
    // libecap::adapter::Service::start();
    // custom code would go here, but this service does not have one
}

void Adapter::Service::stop() {
    // custom code would go here, but this service does not have one
    libecap::adapter::Service::stop();
}

void Adapter::Service::retire() {
    // custom code would go here, but this service does not have one
    libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(const char *url) const {
    return true; // no-op is applied to all messages
}

Adapter::Service::MadeXactionPointer Adapter::Service::makeXaction(libecap::host::Xaction *hostx) {
    return Service::MadeXactionPointer(new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self),
        hostx));
}


Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,
    libecap::host::Xaction *x):
    service(aService),
    hostx(x),
    receivingVb(opUndecided), sendingAb(opUndecided) {
}

Adapter::Xaction::~Xaction() {
    if (libecap::host::Xaction *x = hostx) {
        hostx = 0;
        x->adaptationAborted();
    }
}

const libecap::Area Adapter::Xaction::option(const libecap::Name &) const {
    return libecap::Area(); // this transaction has no meta-information
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &) const {
    // this transaction has no meta-information to pass to the visitor
}

void Adapter::Xaction::start() {

    gzipContext = 0;

    Must(hostx);

    if (hostx->virgin().body()) {
        receivingVb = opOn;
        hostx->vbMake(); // ask host to supply virgin body
    } else {
        // we are not interested in vb if there is not one
        receivingVb = opNever;
    }

    /* adapt message header */

    libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
    Must(adapted != 0);

    // add a custom header
    static const libecap::Name name("X-Ecap");
    const libecap::Header::Value value = libecap::Area::FromTempString("VIGOS eCAP GZIP Adapter");
    adapted->header().add(name, value);
    hostx->useAdapted(adapted);
}

void Adapter::Xaction::stop() {
    hostx = 0;
    // the caller will delete
}

void Adapter::Xaction::abDiscard() {
    Must(sendingAb == opUndecided); // have not started yet
    sendingAb = opNever;
    // we do not need more vb if the host is not interested in ab
    stopVb();
}

void Adapter::Xaction::abMake() {
    Must(sendingAb == opUndecided); // have not yet started or decided not to send
    Must(hostx->virgin().body()); // that is our only source of ab content

    // we are or were receiving vb
    Must(receivingVb == opOn || receivingVb == opComplete);

    sendingAb = opOn;
    hostx->noteAbContentAvailable();
}

void Adapter::Xaction::abMakeMore() {
    Must(receivingVb == opOn); // a precondition for receiving more vb
    hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking() {
    sendingAb = opComplete;
    // we do not need more vb if the host is not interested in more ab
    stopVb();
}

libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size) {
    Must(sendingAb == opOn || sendingAb == opComplete);

    // if complete, there is nothing more to return.
    if (sendingAb == opComplete) {
        return libecap::Area::FromTempString("");
    }

    offset = gzipContext->sendingOffset + offset;
    size = gzipContext->compressedSize - offset;

    return libecap::Area::FromTempBuffer((const char*)&gzipContext->gzipBuffer[offset], size);
}

void Adapter::Xaction::abContentShift(size_type size) {
    Must(sendingAb == opOn || sendingAb == opComplete);
    gzipContext->sendingOffset += size;
    hostx->vbContentShift(gzipContext->lastChunkSize);
}

void Adapter::Xaction::noteVbContentDone(bool atEnd) {

    Must(gzipContext);

    gzipContext->zstream.total_out = 0;

    int rc = deflate(&gzipContext->zstream, Z_FINISH);

    rc = deflateEnd(&gzipContext->zstream);
    gzipContext->compressedSize += gzipContext->zstream.total_out;

    /*
    fprintf(stdout,"Original size: %d\n", gzipContext->originalSize);
    fprintf(stdout,"Compressed size: %d\n", gzipContext->compressedSize);
    fflush(stdout);
    */

    // GZIP Footer
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->checksum & 0xff;
    gzipContext->checksum >>= 8;
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->checksum & 0xff;
    gzipContext->checksum >>= 8;
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->checksum & 0xff;
    gzipContext->checksum >>= 8;
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->checksum & 0xff;

    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->originalSize & 0xff;
    gzipContext->originalSize >>= 8;
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->originalSize & 0xff;
    gzipContext->originalSize >>= 8;
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->originalSize & 0xff;
    gzipContext->originalSize >>= 8;
    gzipContext->gzipBuffer[gzipContext->compressedSize++] = (char) gzipContext->originalSize & 0xff;

    Must(receivingVb == opOn);
    receivingVb = opComplete;
    if (sendingAb == opOn) {
        hostx->noteAbContentDone(atEnd);
        sendingAb = opComplete;
    }

    gzipFinalize();
}

void Adapter::Xaction::noteVbContentAvailable()
{
    Must(receivingVb == opOn);
    Must(gzipContext);

        const libecap::Area vb = hostx->vbContent(0, libecap::nsize); // get all vb

    // calculate original byte size for GZIP footer
    gzipContext->originalSize += vb.size;

    // store chunk size for contentShift()
    gzipContext->lastChunkSize = vb.size;

    // calculate CRC32 for GZIP footer
    gzipContext->checksum = crc32(gzipContext->checksum, (Bytef*)vb.start, vb.size);

    // (re)allocate the gzipBuffer
    gzipContext->gzipBuffer = (unsigned char*) realloc(gzipContext->gzipBuffer, 256 + gzipContext->originalSize);

    // if this is the first content chunk, add the gzip header
    if(gzipContext->originalSize == vb.size) {
        gzipContext->gzipBuffer[0] = (unsigned char) 31;          // Magic number #1
        gzipContext->gzipBuffer[1] = (unsigned char) 139;         // Magic number #2
        gzipContext->gzipBuffer[2] = (unsigned char) Z_DEFLATED;  // Method
        gzipContext->gzipBuffer[3] = (unsigned char) 0;           // Flags
        gzipContext->gzipBuffer[4] = (unsigned char) 0;           // Mtime #1
        gzipContext->gzipBuffer[5] = (unsigned char) 0;           // Mtime #2
        gzipContext->gzipBuffer[6] = (unsigned char) 0;           // Mtime #3
        gzipContext->gzipBuffer[7] = (unsigned char) 0;           // Mtime #4
        gzipContext->gzipBuffer[8] = (unsigned char) 0;           // Extra flags
        gzipContext->gzipBuffer[9] = (unsigned char) 3;           // Operating system: UNIX
        gzipContext->compressedSize = 10;
    }

    gzipContext->zstream.next_in    = (Bytef*) vb.start;
    gzipContext->zstream.avail_in = vb.size;
    gzipContext->zstream.next_out = (Bytef*) &gzipContext->gzipBuffer[gzipContext->compressedSize];
    gzipContext->zstream.avail_out = 256 + gzipContext->originalSize - gzipContext->compressedSize;
    gzipContext->zstream.total_out = 0;

    int rc = deflate(&gzipContext->zstream, Z_SYNC_FLUSH);

    gzipContext->compressedSize += gzipContext->zstream.total_out;

    if(sendingAb == opOn) {
      hostx->noteAbContentAvailable();
    }
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
    if(receivingVb == opOn) {
        hostx->vbStopMaking();
        receivingVb = opComplete;
    } else {
        // we already got the entire body or refused it earlier
        Must(receivingVb != opUndecided);
    }
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall() {
    libecap::host::Xaction *x = hostx;
    Must(x);
    hostx = 0;
    return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered = (libecap::RegisterVersionedService(new Adapter::Service));

