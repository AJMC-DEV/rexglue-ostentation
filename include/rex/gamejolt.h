#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace rex::gamejolt {

enum class SignInState {
  kSignedOut,
  kPending,
  kSignedIn,
  kFailed,
};

void Start(const char* game_id, const char* private_key);

void Stop();

bool IsStarted();

void SignIn(const std::string& username, const std::string& user_token);

void SignOut();

SignInState GetSignInState();

std::string GetUsername();

std::string GetLastError();

void MapTrophy(uint32_t achievement_id, uint32_t trophy_id);

bool LoadTrophyMap(const std::filesystem::path& path);

void AwardTrophy(uint32_t trophy_id);
void RemoveTrophy(uint32_t trophy_id);

void SyncTrophies();

void SetSessionActive(bool active);

}
