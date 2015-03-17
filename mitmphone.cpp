//============================================================================
// Name        : mitmphone.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C, Ansi-style
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pjsip.h>
#include <pjsip_simple.h>
#include <pjsip_ua.h>
#include <pjsua-lib/pjsua.h>
#include <transport_zrtp.h>

#define THIS_FILE "APP"



const char* InfoCodes[] =
{
    "EMPTY",
    "Hello received, preparing a Commit",
    "Commit: Generated a public DH key",
    "Responder: Commit received, preparing DHPart1",
    "DH1Part: Generated a public DH key",
    "Initiator: DHPart1 received, preparing DHPart2",
    "Responder: DHPart2 received, preparing Confirm1",
    "Initiator: Confirm1 received, preparing Confirm2",
    "Responder: Confirm2 received, preparing Conf2Ack",
    "At least one retained secrets matches - security OK",
    "Entered secure state",
    "No more security for this session"
};

/**
 * Sub-codes for Warning
 */
const char* WarningCodes [] =
{
    "EMPTY",
    "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096",
    "Received a GoClear message",
    "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096",
    "No retained shared secrets available - must verify SAS",
    "Internal ZRTP packet checksum mismatch - packet dropped",
    "Dropping packet because SRTP authentication failed!",
    "Dropping packet because SRTP replay check failed!",
    "Valid retained shared secrets availabe but no matches found - must verify SAS"
};

/**
 * Sub-codes for Severe
 */
const char* SevereCodes[] =
{
    "EMPTY",
    "Hash HMAC check of Hello failed!",
    "Hash HMAC check of Commit failed!",
    "Hash HMAC check of DHPart1 failed!",
    "Hash HMAC check of DHPart2 failed!",
    "Cannot send data - connection or peer down?",
    "Internal protocol error occured!",
    "Cannot start a timer - internal resources exhausted?",
    "Too much retries during ZRTP negotiation - connection or peer down?"
};

static void secureOn(void* data, char* cipher)
{
    PJ_LOG(3,(THIS_FILE, "Security enabled, cipher: %s", cipher));
}
static void secureOff(void* data)
{
    PJ_LOG(3,(THIS_FILE, "Security disabled"));
}
static void showSAS(void* data, char* sas, int32_t verified)
{
    PJ_LOG(3,(THIS_FILE, "SAS data: %s, verified: %d", sas, verified));
}
static void confirmGoClear(void* data)
{
    PJ_LOG(3,(THIS_FILE, "GoClear????????"));
}
static void showMessage(void* data, int32_t sev, int32_t subCode)
{
    switch (sev)
    {
        case zrtp_Info:
            PJ_LOG(3,(THIS_FILE, "ZRTP info message: %s", InfoCodes[subCode]));
            break;

        case zrtp_Warning:
            PJ_LOG(3,(THIS_FILE, "ZRTP warning message: %s", WarningCodes[subCode]));
            break;

        case zrtp_Severe:
            PJ_LOG(3,(THIS_FILE, "ZRTP severe message: %s", SevereCodes[subCode]));
            break;

        case zrtp_ZrtpError:
            PJ_LOG(3,(THIS_FILE, "ZRTP Error: severity: %d, subcode: %x", sev, subCode));
            break;
    }
}
static void zrtpNegotiationFailed(void* data, int32_t severity, int32_t subCode)
{
    PJ_LOG(3,(THIS_FILE, "ZRTP failed: %d, subcode: %d", severity, subCode));
}
static void zrtpNotSuppOther(void* data)
{
    PJ_LOG(3,(THIS_FILE, "ZRTP not supported by other peer"));
}
static void zrtpAskEnrollment(void* data, int32_t info)
{
    PJ_LOG(3,(THIS_FILE, "ZRTP - Ask PBX enrollment"));
}
static void zrtpInformEnrollment(void* data, int32_t info)
{
    PJ_LOG(3,(THIS_FILE, "ZRTP - Inform PBX enrollement"));
}
static void signSAS(void* data, unsigned char* sas)
{
    PJ_LOG(3,(THIS_FILE, "ZRTP - sign SAS"));
}
static int32_t checkSASSignature(void* data, unsigned char* sas)
{
    PJ_LOG(3,(THIS_FILE, "ZRTP - check SAS signature"));
}

static zrtp_UserCallbacks usercb =
{
    &secureOn,
    &secureOff,
    &showSAS,
    &confirmGoClear,
    &showMessage,
    &zrtpNegotiationFailed,
    &zrtpNotSuppOther,
    &zrtpAskEnrollment,
    &zrtpInformEnrollment,
    &signSAS,
    &checkSASSignature,
    NULL
};

/* Display error and exit application */
static void error_exit(const char *title, pj_status_t status)
{
	pjsua_perror(THIS_FILE, title, status);
	pjsua_destroy();
	exit(1);
}

/* Initialize the ZRTP transport and the user callbacks */
pjmedia_transport* on_create_media_transport(pjsua_call_id call_id,
                                             unsigned media_idx,
                                             pjmedia_transport *base_tp,
                                             unsigned flags)
{
    pjmedia_transport *zrtp_tp = NULL;
    pj_status_t status;
    pjmedia_endpt* endpt = pjsua_get_pjmedia_endpt();

    PJ_LOG(3,(THIS_FILE, "ZRTP transport created"));
    status = pjmedia_transport_zrtp_create(endpt, NULL, base_tp, &zrtp_tp, flags);

    usercb.userData = zrtp_tp;

    /* this is optional but highly recommended to enable the application
     * to report status information to the user, such as verfication status,
     * SAS code, etc
     */
    pjmedia_transport_zrtp_setUserCallback(zrtp_tp, &usercb);

    /*
     * Initialize the transport. Just the filename of the ZID file that holds
     * our partners ZID, shared data etc. If the files does not exists it will
     * be created and initialized.
     */
    pjmedia_transport_zrtp_initialize(zrtp_tp, "simple.zid", PJ_TRUE);
    return zrtp_tp;
}


/* Callback called by the library upon receiving incoming call */
static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data *rdata)
{
	pjsua_call_info ci;

	PJ_UNUSED_ARG(acc_id);
	PJ_UNUSED_ARG(rdata);

	pjsua_call_get_info(call_id, &ci);

	PJ_LOG(3,(THIS_FILE, "Incoming call from %.*s", (int)ci.remote_info.slen,	ci.remote_info.ptr));

	// place a call to gregor in between. 'sip:gregor..' is just a placeholder.
	pj_status_t status;
	pj_str_t uri = pj_str("sip:gregor@127.0.0.1");

	printf("placing a call to gregor\n");
	status = pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, NULL);
	if (status != PJ_SUCCESS) error_exit("Error making call to gregor", status);

	/* Automatically answer incoming calls with 200/OK */
	pjsua_call_answer(call_id, 200, NULL, NULL);
}

/* Callback called by the library when call's state has changed */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e)
{
	pjsua_call_info ci;

	PJ_UNUSED_ARG(e);

	pjsua_call_get_info(call_id, &ci);

	PJ_LOG(3,(THIS_FILE, "Call %d state=%.*s", call_id,	(int)ci.state_text.slen, ci.state_text.ptr));
}

/* Callback called by the library when call's media state has changed */
static void on_call_media_state(pjsua_call_id call_id)
{
	PJ_LOG(3, (THIS_FILE, "Entering: on_call_media_state"));

	pjsua_call_info ci;
	pjsua_call_get_info(call_id, &ci);

	pj_status_t status;

	if (ci.media_status == PJSUA_CALL_MEDIA_ACTIVE) {
		pjsua_conf_connect(pjsua_call_get_conf_port(call_id), 0);
		pjsua_conf_connect(0, pjsua_call_get_conf_port(call_id));
	}

}


int main(int argc, char *argv[]) {
	pjsua_acc_id acc_id;
	pj_status_t status;

	// Create pjsua
	status = pjsua_create();
	if (status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "Error in pjsua_create()", status);
		return 1;
	}

	// If argument is specified, it's got to be a valid SIP URL
	if (argc > 1) {
		status = pjsua_verify_url(argv[1]);
		if (status != PJ_SUCCESS) {
			pjsua_perror(THIS_FILE, "Invalid URL in argv", status);
		}
	}

	// Init pjsua
	{
		pjsua_config cfg;
		pjsua_logging_config log_cfg;

		pjsua_config_default(&cfg);
		cfg.cb.on_incoming_call = &on_incoming_call;
		cfg.cb.on_call_media_state = &on_call_media_state;
		cfg.cb.on_call_state = &on_call_state;
		/*
		 * Register the ZRTP created callback that sets up the ZRTP stuff
		 *
		 * This call is available only after you applied the patch to pjsip
		 * (see top level directory)
		 */
		cfg.cb.on_create_media_transport = &on_create_media_transport;
		// cfg.outbound_proxy[cfg.outbound_proxy_cnt++] = pj_str(SIP_OUTBOUND_PROXY);

		pjsua_logging_config_default(&log_cfg);
		log_cfg.console_level = 4;

		// Initialize media configuration
	 	pjsua_media_config med_cfg;
	 	pjsua_media_config_default(&med_cfg);
	 	med_cfg.clock_rate = 44100;
	 	PJ_LOG(3, (THIS_FILE, "media cfg:"));
	 	PJ_LOG(3, (THIS_FILE, "clock rate: %d - snd clock rate: %d\n", med_cfg.clock_rate, med_cfg.snd_clock_rate));

		status = pjsua_init(&cfg, &log_cfg, &med_cfg);
		if (status != PJ_SUCCESS) error_exit("Error in pjsua_init()", status);
	}

	// Set Codec "ITU-T G.711 PCMU aka PCMU/8000/1" to highest priority. (cause sflphone thinks speex/16000 is type 111 instead of 98)
	pj_str_t codec_str = pj_str("PCMU/8000");
	pjsua_codec_set_priority(&codec_str, 132);

	// Add UDP transport.
	{
		pjsua_transport_config cfg;

		pjsua_transport_config_default(&cfg);
		cfg.port = 5070;
		status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &cfg, NULL);
		if (status != PJ_SUCCESS) error_exit("Error creating transport", status);
	}

	// Initialization is done, now start pjsua
	status = pjsua_start();
	if (status != PJ_SUCCESS) error_exit("Error starting pjsua", status);

	// Register to SIP server by creating SIP account.
	{
		pjsua_acc_config cfg;

		pjsua_acc_config_default(&cfg);
		cfg.id = pj_str("sip:mitm@127.0.0.1");
		cfg.reg_uri = pj_str("sip:127.0.0.1");
		cfg.cred_count = 1;
		cfg.cred_info[0].realm = pj_str("127.0.0.1");
		cfg.cred_info[0].scheme = pj_str("digest");
		cfg.cred_info[0].username = pj_str("mitm");
		cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
		cfg.cred_info[0].data = pj_str("secret1");

		status = pjsua_acc_add(&cfg, PJ_TRUE, &acc_id);
		if (status != PJ_SUCCESS) error_exit("Error adding account", status);
	}

	// -------------------------------------- debug -----------------------
	// get all available audio devices.
	pjmedia_aud_dev_info info[100];
	unsigned count = 100;

	status = pjsua_enum_aud_devs(info,&count);

	if (status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "Error getting installed audio devices", status);
		return 1;
	}
	PJ_LOG(3, (THIS_FILE, "Detected audio devices: %d. Namely:", count));
	int pulseID = 0; // save the position of the "pulse" device, it's the one that works.
	int i = 0;
	for (i = 0; i < count; i++) {
		PJ_LOG(3, (THIS_FILE, "name: %s - input_count: %d - output_count: %d - def samples per s: %d - driver: %s\n",
				info[i].name,info[i].input_count,info[i].output_count, info[i].default_samples_per_sec, info[i].driver));
	}
	// todo free something?
	// -------------------------------------- debug end -----------------------

	// Pjsua does not seem to detect all sound devices reliably.
	// Thus the first two devices, which should be the standard capture (0) and standard playback (1) devices, are chosen always.
	status = pjsua_set_snd_dev(0,1);
	if (status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "Error setting sound devices to 0 - 1", status);
		return 1;
	}

	// If URL is specified, make call to the URL.
	if (argc > 1) {
		pj_str_t uri = pj_str(argv[1]);
		status = pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, NULL);
		if (status != PJ_SUCCESS) error_exit("Error making call", status);
	}
	// Wait until user press "q" to quit.
	for (;;) {
		char option[10];

		puts("Press 'h' to hangup all calls, 'q' to quit, c to call silas.");
		if (fgets(option, sizeof(option), stdin) == NULL) {
			puts("EOF while reading stdin, will quit now..");
			break;
		}

		if (option[0] == 'q')
			break;


		if (option[0] == 'h')
			pjsua_call_hangup_all();

		if (option[0] == 'c') {
			pj_str_t uri = pj_str("sip:silas@127.0.0.1"); // TODO Debug
			status = pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, NULL);
			if (status != PJ_SUCCESS) error_exit("Error making call to silas", status);
		}

	}


	pjsua_destroy();



	return EXIT_SUCCESS;
}
