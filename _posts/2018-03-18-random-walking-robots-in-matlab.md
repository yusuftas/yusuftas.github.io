---
title: "Random Walking Robots in Matlab"
date: 2018-03-18
categories: 
  - "general-programming"
tags: 
  - "cell-array"
  - "matlab"
  - "random"
  - "random-walk"
  - "random-walking"
  - "struct"
---

Hi Everyone,

In this post, I wanted share my experience of coding random walking in matlab. This was a little lecture problem for one of the courses I was tutoring. Problem is to simulate random walking robots in a 2D field:

1. There will be several robots in the field. Configuration of the map should be read from a file. File will respectively include : size of the field (w,h) ; number of robots; position and color marker for the each robot line by line e.g 10,10,bo
2. Each robot will move randomly in one of the 4 directions: up,down,left,right
3. When a robot has picked a direction to move, if another robot is occupying that position, it should not move for this turn.
4. When a robot reaches any of the boundaries, it should stop.
5. Animation should end when all of the given robots stops.

Let's start with a visualization of what we are trying to get :

![Random walking robots simulation](/assets/img/rnd_walk2_forblog_2.gif)

To solve this problem we will need several things. We need to read the configuration from a file, we need to generate the map plot with given settings and then generate the simulation with the given specifications. Now lets start with reading the input file.

<!--more-->

Lets first check a simple configuration file we can use:

```
12,12
4
4,4,bo
9,9,go
9,4,yo
4,9,ko
```

We can use **fscanf** to read formatted inputs . We will use a struct to hold information of a robot. It helps us to symbolize the information and put them all in a single container. Since we will have multiple robots, to hold information of each robot we will utilize a cell array. Each element in the cell array will be a struct of a robot:

```matlab
config      = 'random_robots.config';
marker_size = 50;

fileID = fopen(config,'r');

field_size = fscanf(fileID,'%d,%d\n',2)
robot_count = fscanf(fileID, '%d\n',1);
    
robots = {};

for i=1:robot_count
    
    robot_position = fscanf(fileID,'%d,%d,',2);
    color = fscanf(fileID,'%s\n',1);
    
    robot.x = robot_position(1);
    robot.y = robot_position(2);
    robot.mark = color;
    robot.size   = marker_size;
    robot.isStopped = false;
    
    robots{i} = robot;
    
end

fclose(fileID);
```

Another requirement of this problem is that two robots can't occupy a position in the map. Robots should not move if there is another robot in the position they are trying to move. To simulate this, we need to know where each robot is in the field. We will hold this information in a matrix, if the position in the matrix is 0 then this position is empty, if it is 1, then it means there is already a robot in that position. When moving the robots, your code should clear the position in the map matrix, and set 1 to the moved position.

```matlab
all_field = zeros(fieldx,fieldy);

for i=1:robot_count
    robots{i}.handle =  scatter(robots{i}.x,robots{i}.y,robots{i}.size,robots{i}.mark,'filled'); 
    
    %robot occupies the position in the map
    all_field(robots{i}.x,robots{i}.y) = 1;     
    
end
```

To simulate the random direction picking we can use rand or randi function. To simplify it, we can use randi function to pick a random integer from 1:4 , and for each number we can use different direction. You should do this for each robot and after each move you need to check if it is a valid move meaning that there is no other robot occupying that position.

```matlab
    for i=1:robot_count
    
        robot = robots{i};
        
        if robot.isStopped
            continue;
        end
        
        newx = robot.x;
        newy = robot.y;
        
        rand_num = randi([1,4],1);

        if rand_num == 1
            newy = newy + 1;
        elseif rand_num == 2
            newy = newy - 1;
        elseif rand_num == 3
            newx = newx - 1;
        elseif rand_num == 4
            newx = newx + 1;
        end        
        
        
        %check if place is empty before moving
        
        if all_field(newx,newy) == 1    %occupied dont move
            continue;
        end
    end
```

Only few pieces left before reaching the end goal. After randomly generating a move, if the robot reached a boundary, it should stop moving. And when all robots stopped moving, we can stop the simulation. It is easy to check the running robots with a counter. Checking the boundary is simply checking x and y position of the robot:

```matlab
        if robots{i}.x == 1 || robots{i}.y == 1 || robots{i}.x == fieldx || robots{i}.y == fieldy
            robots{i}.isStopped = true;
            num_running_robots = num_running_robots - 1;
        end
```

Now we are nearly there. Only animation part is left. **You can create a plot animation in Matlab by simply deleting the old point and then replotting the figure**. Also adding some delays by using **pause(0.2)** you can plot the animation every 0.2 seconds.

```matlab
    delete(robots{i}.handle);
    robots{i}.handle= scatter(robot.x,robot.y,robot.size,robot.mark,'filled');

    pause(0.2); 
```

That is basically it. You just need to combine all these pieces with appropriate functions and a script. Or you can get the ready code and a live script version from my Github :)

I hope you've learned something from this post, you stranger in front of the screen. Let me know if there is any mistake, or if you have any questions. See you soon.

**EDIT:** You can find the related codes in my github : [Random walking robots in matlab](https://github.com/yusuftas/blog_matlab_codes/tree/master/random_walking_robots)
