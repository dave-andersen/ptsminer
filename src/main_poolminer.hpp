#if defined(__MINGW64__)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <cstring>

#define TIMING_DEBUG 0

#if TIMING_DEBUG
#include <sys/time.h>
#endif

extern "C" {
#include "sph_sha2.h"
}
#include "cpuid.h"
#include "sha512.h"

enum SHAMODE { SPHLIB = 0, AVXSSE4, AVX2 };

typedef struct {
  // comments: BYTES <index> + <length>
  int32_t nVersion;            // 0+4
  uint8_t hashPrevBlock[32];       // 4+32
  uint8_t hashMerkleRoot[32];      // 36+32
  uint32_t  nTime;               // 68+4
  uint32_t  nBits;               // 72+4
  uint32_t  nNonce;              // 76+4
  uint32_t  birthdayA;          // 80+32+4 (uint32_t)
  uint32_t  birthdayB;          // 84+32+4 (uint32_t)
  uint8_t   targetShare[32];
} blockHeader_t;              // = 80+32+8 bytes header (80 default + 8 birthdayA&B + 32 target)

class CBlockProvider {
public:
	CBlockProvider() { }
	~CBlockProvider() { }
	virtual blockHeader_t* getBlock(unsigned int thread_id, unsigned int last_time, unsigned int counter) = 0;
	virtual blockHeader_t* getOriginalBlock() = 0;
	virtual void setBlockTo(blockHeader_t* newblock) = 0;
	virtual void submitBlock(blockHeader_t* block, unsigned int thread_id) = 0;
	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) = 0;
};

volatile uint64_t totalCollisionCount = 0;
volatile uint64_t totalShareCount = 0;

#define MAX_MOMENTUM_NONCE (1<<26) // 67.108.864
#define SEARCH_SPACE_BITS  50
#define BIRTHDAYS_PER_HASH 8

#define PARTITION_BITS 11 // #parts is 2^(bits)
#define NUM_PARTITIONS (1<<(PARTITION_BITS))
#define PARTITION_START_OFFSET 2
// Be conservative:  Some partitions larger than others, so we can't
// always count on saving all of the bits.  4 partitions can save us 1.
#define COLLISION_SHIFT (PARTITION_BITS-1)
#define IDX_SIZE (26-COLLISION_SHIFT)

void print256(const char* bfstr, uint32_t* v) {
	std::stringstream ss;
	for(ptrdiff_t i=7; i>=0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << v[i];
    ss.flush();
    std::cout << bfstr << ": " << ss.str().c_str() << std::endl;
}

template<SHAMODE shamode>
bool protoshares_revalidateCollision(blockHeader_t* block, uint8_t* midHash, uint32_t indexA, uint32_t indexB, uint64_t birthdayB, CBlockProvider* bp, unsigned int thread_id)
{
        //if( indexA > MAX_MOMENTUM_NONCE )
        //        printf("indexA out of range\n");
        //if( indexB > MAX_MOMENTUM_NONCE )
        //        printf("indexB out of range\n");
        //if( indexA == indexB )
        //        printf("indexA == indexB");
        uint8_t tempHash[32+4];
        uint64_t resultHash[8];
        memcpy(tempHash+4, midHash, 32);
	uint64_t birthdayA;
	if (shamode == AVXSSE4 || shamode == AVX2) {
	  // get birthday A
	  *(uint32_t*)tempHash = indexA&~7;
	  //AVX/SSE			
	  SHA512_Context c512_avxsse;
	  SHA512_Init(&c512_avxsse);
	  SHA512_Update(&c512_avxsse, tempHash, 32+4);
	  SHA512_Final(&c512_avxsse, (unsigned char*)resultHash);
	  birthdayA = resultHash[ptrdiff_t(indexA&7)] >> (64ULL-SEARCH_SPACE_BITS);
	  if (!birthdayB) {
	    *(uint32_t*)tempHash = indexB&~7;
	    SHA512_Init(&c512_avxsse);
	    SHA512_Update(&c512_avxsse, tempHash, 32+4);
	    SHA512_Final(&c512_avxsse, (unsigned char*)resultHash);
	    birthdayB = resultHash[ptrdiff_t(indexB&7)] >> (64ULL-SEARCH_SPACE_BITS);
	  }
	} else {
	  // get birthday A
	  *(uint32_t*)tempHash = indexA&~7;
	  //SPH
	  sph_sha512_context c512_sph;
	  sph_sha512_init(&c512_sph);
	  sph_sha512(&c512_sph, tempHash, 32+4);
	  sph_sha512_close(&c512_sph, (unsigned char*)resultHash);
	  birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	  // get birthday B
	  if (!birthdayB) {
	    *(uint32_t*)tempHash = indexB&~7;
	    sph_sha512_init(&c512_sph);
	    sph_sha512(&c512_sph, tempHash, 32+4);
	    sph_sha512_close(&c512_sph, (unsigned char*)resultHash);
	    birthdayB = resultHash[ptrdiff_t(indexB&7)] >> (64ULL-SEARCH_SPACE_BITS);
	  }
	}
        if( birthdayA != birthdayB )
        {
                return false; // invalid collision
        }
        // birthday collision found
        totalCollisionCount += 2; // we can use every collision twice -> A B and B A (srsly?)
        //printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
        
		sph_sha256_context c256; //SPH
		
		// get full block hash (for A B)
        block->birthdayA = indexA;
        block->birthdayB = indexB;
        uint8_t proofOfWorkHash[32];        
		//SPH
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)block, 80+8);
		sph_sha256_close(&c256, proofOfWorkHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
		sph_sha256_close(&c256, proofOfWorkHash);
        bool hashMeetsTarget = true;
        uint32_t* generatedHash32 = (uint32_t*)proofOfWorkHash;
        uint32_t* targetHash32 = (uint32_t*)block->targetShare;
        for(uint64_t hc=7; hc!=0; hc--)
        {
                if( generatedHash32[hc] < targetHash32[hc] )
                {
                        hashMeetsTarget = true;
                        break;
                }
                else if( generatedHash32[hc] > targetHash32[hc] )
                {
                        hashMeetsTarget = false;
                        break;
                }
        }
        if( hashMeetsTarget )
			bp->submitBlock(block, thread_id);
		
        // get full block hash (for B A)
        block->birthdayA = indexB;
        block->birthdayB = indexA;
		//SPH
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)block, 80+8);
		sph_sha256_close(&c256, proofOfWorkHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
		sph_sha256_close(&c256, proofOfWorkHash);
        hashMeetsTarget = true;
        generatedHash32 = (uint32_t*)proofOfWorkHash;
        targetHash32 = (uint32_t*)block->targetShare;
        for(uint64_t hc=7; hc!=0; hc--)
        {
                if( generatedHash32[hc] < targetHash32[hc] )
                {
                        hashMeetsTarget = true;
                        break;
                }
                else if( generatedHash32[hc] > targetHash32[hc] )
                {
                        hashMeetsTarget = false;
                        break;
                }
        }
        if( hashMeetsTarget )
			bp->submitBlock(block, thread_id);

		return true;
}


inline void put_hash_in_bucket(uint64_t hashval, uint64_t *hashMap, uint32_t *hashOffsets, uint32_t nonce) {
  uint32_t bin = (hashval >> (64 - SEARCH_SPACE_BITS)) % NUM_PARTITIONS;
  hashval &= ~(MAX_MOMENTUM_NONCE-1);
  hashval |= nonce;
  hashMap[hashOffsets[bin]] = hashval;
  hashOffsets[bin]++;
}

double timeval_diff(const struct timeval * const start, const struct timeval * const end)
{
    /* Calculate the second difference*/
    double r = end->tv_sec - start->tv_sec;

    /* Calculate the microsecond difference */
    if (end->tv_usec > start->tv_usec)
        r += (end->tv_usec - start->tv_usec)/1000000.0;
    else if (end->tv_usec < start->tv_usec)
        r -= (start->tv_usec - end->tv_usec)/1000000.0;

    return r;
}

template<int COLLISION_TABLE_SIZE, int COLLISION_KEY_MASK, int COLLISION_TABLE_BITS, SHAMODE shamode>
void protoshares_process_512(blockHeader_t* block, uint32_t* collisionIndices, uint64_t *hashMap, CBlockProvider* bp, unsigned int thread_id)
{
  // generate mid hash using sha256 (header hash)
  blockHeader_t* ob = bp->getOriginalBlock();
  uint8_t midHash[32+4];
  {
    //SPH
    sph_sha256_context c256;
    sph_sha256_init(&c256);
    sph_sha256(&c256, (unsigned char*)block, 80);
    sph_sha256_close(&c256, midHash+4);
    sph_sha256_init(&c256);
    sph_sha256(&c256, (unsigned char*)(midHash+4), 32);
    sph_sha256_close(&c256, midHash+4);
  }

  // start search
  SHA512_Context c512_avxsse; //AVX/SSE
  uint64_t resultHash[8];
  
  SHA512_Init(&c512_avxsse);
  SHA512_Update(&c512_avxsse, midHash, 32+4);
  SHA512_PreFinal(&c512_avxsse);
  int revalidate = 0, doublecheck = 0;
  
  uint32_t hash_counts[NUM_PARTITIONS];
  for (int i = 0; i < NUM_PARTITIONS; i++) { 
    uint32_t bin_offset = (i*(MAX_MOMENTUM_NONCE/NUM_PARTITIONS))*PARTITION_START_OFFSET;
    hash_counts[i] = bin_offset;
  }
  
#if TIMING_DEBUG
  struct timeval tv_start, tv_end, tv_scan_end;
  gettimeofday(&tv_start, NULL);
#endif


  for (uint32_t n = 0; n < MAX_MOMENTUM_NONCE; n+= BIRTHDAYS_PER_HASH) {
    SHA512_Final_Shift(&c512_avxsse, n, (uint8_t *)resultHash);
    for (uint32_t i = 0; i < 8; i++) {
      put_hash_in_bucket(resultHash[i], hashMap, hash_counts, n+i);
    }
  }
#if TIMING_DEBUG
  gettimeofday(&tv_end, NULL);
#endif

  for (int bin = 0; bin < NUM_PARTITIONS; bin++) {
    memset(collisionIndices, 0x00, sizeof(uint32_t)*COLLISION_TABLE_SIZE);
    uint32_t bin_offset = (bin*(MAX_MOMENTUM_NONCE/NUM_PARTITIONS))*PARTITION_START_OFFSET;
    int binlimit = hash_counts[bin];
    //    printf("bin %d at %lu has %d hashes\n", bin, bin_offset, hash_counts[bin]); fflush(stdout);
    for (uint32_t binloc = bin_offset; binloc < binlimit; binloc++) {

#define N_PREFETCH 8
      if ((binloc+N_PREFETCH) < binlimit) {
	uint64_t prefetchAddress = hashMap[binloc+N_PREFETCH] >> (64 - COLLISION_TABLE_BITS);
	__builtin_prefetch(&collisionIndices[prefetchAddress]);
      }

      uint64_t birthday = hashMap[binloc];
      uint32_t collisionKey = (uint32_t)(birthday >> COLLISION_SHIFT) & (~((1UL<<IDX_SIZE)-1));
      uint32_t idx = (uint32_t)birthday & ((1UL<<26)-1);
      birthday >>= (64 - COLLISION_TABLE_BITS);
      uint32_t ck = collisionIndices[birthday];
      //      printf("bd64 %llx   ck %lx  idx %lx  bday %lx ck %lx\n",
      //     hashMap[binloc], collisionKey, idx, birthday, ck);
      
      if (ck && (ck & (~((1UL<<IDX_SIZE)-1))) == collisionKey) {
		doublecheck++;
	uint32_t cloc = (ck & ((1UL<<IDX_SIZE)-1));
	//printf("partial collision %lx  %lx  %u\n", birthday, ck, cloc);
	uint64_t actualblock = hashMap[cloc+bin_offset];
	if ((actualblock >> 26) == (hashMap[binloc] >> 26)) {
	  uint32_t otheridx = actualblock & ((1UL<<26)-1);
	  protoshares_revalidateCollision<shamode>(block, midHash+4, otheridx, idx, 0, bp, thread_id);
	  revalidate++;
	}
      }

      collisionIndices[birthday] = collisionKey | (binloc - bin_offset);
    }
  }
  //  printf("reval: %d  doublecheck: %d\n", revalidate, doublecheck);
#if TIMING_DEBUG
  gettimeofday(&tv_scan_end, NULL);
  printf("Gen %4.4f   Scan:  %4.4f  reval %d  dcheck %d\n", timeval_diff(&tv_start, &tv_end),
	 timeval_diff(&tv_end, &tv_scan_end), revalidate, doublecheck);
#endif

} 
