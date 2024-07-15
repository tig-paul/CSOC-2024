# Writeups for CSOC-Project 1
---
# Analysing a savefile Format
---
## Overview:

The goal of the project is to access the savefile of a game and make a deep research on how each chunk of the file works and how can we modify it according to our choice.

## Outline:

1. Choose a game.
2. Get access to its savefile.
3. Analyse the savefile by changing the game values and comparing with previous savefiles.
4. Identify what each chunk of the savefile does.
5. Come up with a method to be able to edit the savefile according to our choice.

## Tools:

**Text Editor**: An editor in which we can open the savefile and edit its contents.

## Methodology:
    
 1. **Installation**:
   
    I installed a chess game from the app store.

 2. **Getting access to the savefile**:

    First, I searched a lot for its savefile in the finder but could not locate it. Then while playing the game, I figured it out that simply saving the game with 'command'+'s' opens the page to give the path of the savefile to be stored. So, I made a `tmp` directory and saved the file there. 
 3. **Editing the savefile**:
   
    From the `tmp` directory, I opened the savefile using my `TextEdit` editor and changed the progress values according to my choice.

## Video Explanation:

[![Savefile Editing](https://img.youtube.com/vi/Ud7OlH73U7U/0.jpg)](https://www.youtube.com/watch?v=Ud7OlH73U7U)

## Result:

By changing the progress values, I easily manipulated the game and got the result I wanted.
   
## Conclusion:

The location of game savefiles varies for different games and devices. First, we have to find the correct location by roaming here and there and googling. Once we have found it, in some cases we can analyse it manually. But we can't do the same for the games where the encoding process is much advanced(most of the cases they are base64 encoded) or it is not handy. Then we can use several save editors, for example [this](https://rakion99.github.io/shelter-editor/) one. In this way, we can manipulate the game as we want. By the way, in some games the files are encrypted and hence can't be modified.
