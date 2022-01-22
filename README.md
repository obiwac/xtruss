# xtruss

Fork of [xtruss](https://www.chiark.greenend.org.uk/~sgtatham/xtruss/), so that I can extend it as needed.
Original README file can be found at `/README`.

## Updating

The source can be updated by merging from the [upstream branch](https://git.tartarus.org/simon/xtruss.git):

```sh
% git merge https://git.tartarus.org/simon/xtruss.git
```

## Building

Run:

```sh
% mkdir build
% cd build
% cmake ..
% make -j<however many threads you have>
```

Your `xtruss` executable will be at `build/xtruss`.
