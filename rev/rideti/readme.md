1. We can see `CONGRATULATIONS!` in the exe file, so this could be our goal.
2. Ida doesn't recognize the string, so we create a `string` structure manually, then apply it to the string we found.

```
len       dd
unknown1  dd
unknown2  dd
unknown3  dd
string    db 16 (dup?)
```

3. `gameDraw_main_1429` shows that we need to set `scene_state = 2` to goto the win scene.
4. `update_game_main_976` contains most of the main game logic. We can see that when `score = 3962971405739`, the `scene_state` will be set to `2`. So I use x64dbg to go to this check spot, then manually set the score to win.
