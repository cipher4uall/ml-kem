#include "test_kyber.hpp"
#include <iostream>

int
main()
{
  test_kyber::test_field_ops();
  std::cout << "[test] Kyber prime field operations" << std::endl;

  test_kyber::test_ntt_intt();
  std::cout << "[test] (i)NTT over degree-255 polynomial R_q | q = 3329"
            << std::endl;

  test_kyber::test_serialization<12>();
  test_kyber::test_serialization<11>();
  test_kyber::test_serialization<10>();
  test_kyber::test_serialization<9>();
  test_kyber::test_serialization<8>();
  test_kyber::test_serialization<7>();
  test_kyber::test_serialization<6>();
  test_kyber::test_serialization<5>();
  test_kyber::test_serialization<4>();
  test_kyber::test_serialization<3>();
  test_kyber::test_serialization<2>();
  test_kyber::test_serialization<1>();
  std::cout << "[test] Polynomial serialization/ deserialization" << std::endl;

  test_kyber::test_compression<11>();
  test_kyber::test_compression<10>();
  test_kyber::test_compression<5>();
  test_kyber::test_compression<4>();
  test_kyber::test_compression<1>();
  std::cout << "[test] Coefficient compression/ decompression" << std::endl;

  test_kyber::test_kyber_cpa_pke<2, 3, 2, 10, 4>(); // kyber-512
  test_kyber::test_kyber_cpa_pke<3, 2, 2, 10, 4>(); // kyber-768
  test_kyber::test_kyber_cpa_pke<4, 2, 2, 11, 5>(); // kyber-1024
  std::cout << "[test] INDCPA-secure Public Key Encryption" << std::endl;

  return EXIT_SUCCESS;
}