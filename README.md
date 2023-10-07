Many thanks to  @riester / @Riesters  for his help. He really helped a lot. Without him, I would never have done it.
---------------------------------------------------------------------------------------
Demonstration that this works: https://youtu.be/i1Z29zio3tM
---------------------------------------------------------------------------------------
You can repeat process by edit exe of the game via any hex editor without IDA pro. Just open this list: https://github.com/Max-RM/Extend-PistonPushLimit-for-MCBE/blob/main/Patch-list_for_MCBE-UWP-x64.txt
with needed hex positions and then using any hex editor go to this position and change (OC) to (FF).

(Not all version will be supported becouse it's hard to edit game binarys via IDA pro. The currently supported platforms and Architectures: MCBE Windows UWP x64). 
Todo list: 
MCBE Windows UWP x86;
MCBE Windows UWP ARM (There is only ARM32 MCBE for Windows ARM64, but unfortunately there is no ARM64 MCBE for Windows ARM64);

MCBE Windows win32 x86 McChinaDev (McChinaDev (MCBE development versions by Netease that even support Windows 7) that distributed by MDLC organization);
MCEE Windows win32 x86 MCEE/Opticraft (This is Minecraft Education Edition, Opticraft is modified MCEE, they both works on Windows 7 too);
MCBE windows win32 x86/x64 (Some strange x86/x64 Chinese versions by Netease (non-dev versions) and chinese MCEE x64);
MCBE Windows win32 x64 BDS (Bedrock Dedicated Server to host MCBE worlds);

MCBE Android ARM32v7;
MCBE Android ARm64v8;
MCBE Android x86 (for Android x86, this is OS that can be installed on almost any PC and for ChromeOS (not recommended, Android x86 better));
MCBE Android x86_x64 (for Android x86, this is OS that can be installed on almost any PC and for ChromeOS (not recommended, Android x86 better));

Todo list?(not sure that will support them):
MCBE IOS ARM;
MCEE MacOS x64 (Minecraft Education Edition for MacOS x64);
MCBE Linux x64 BDS (Bedrock Dedicated Server to host MCBE worlds);
MCEE Android ARM32v7/ARM64v8/x86/x86_x64 (Not deserve be modded becouse useless);
MCBE-trial Android ARM32v7/ARM64v8/x86/x86_x64 (Not deserve be modded becouse useless);
---------------------------------------------------------------------------------------
If you have any problems with this or you want to ask for support other versions that not in the list (Only MBE UWP x64/x86 is supported now) then ask help here: https://github.com/Max-RM/Extend-PistonPushLimit-for-MCBE/issues
---------------------------------------------------------------------------------------
Later I will make manual how to modify the game via IDA pro (if there is no hex positions for your version of the game you will use this method via IDA pro).
