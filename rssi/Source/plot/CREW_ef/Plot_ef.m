% Measurement points
x = [2.02,2.17,3.51,5.16,5.39,8.48,9.81,11.57,11.57,14.48,16.12,17.56,17.59,20.54,20.71,22.08,23.9,26.53,26.68,30.28];
y = [10.98,4.98,9.02,10.94,5.06,1.93,9.02,5.06,1.89,10.95,9.02,5.06,10.95,10.94,1.65,9.02,1.67,5.39,9.03,1.67];

% Datasets

% Small_Mean 
zRef_Ex_1_Mean = {-37.67,-50.4,-39.93,-28.2,-41,-47.47,-47.4,-62.2,-68.6,-45.33,-57.2,-70.93,-56.13,-58.93,-75.33,-60.53,-79.53,-81,-77.93,-83.73}; 
zRef_Ex_2_Mean = {-43.83,-59,-41.75,-39.58,-53.67,-50.5,-54.75,-67.08,-72.75,-60.67,-62.08,-75,-63.08,'No Data',-74.6,-66.33,-84.2,-81.92,-77.64,'No Data'}; 
zRef_Ex_3_Mean = {-53.2,-60.95,-52.9,-43.05,-47.25,-55.1,-56.55,-73.1,-69.45,-51.75,-65.3,-75.35,-62.65,-67.3,-80.67,-70.4,-75.65,-86,-75.15,-82.19}; 
zRef_Ex_4_Mean = {-49.5,-54.6,-51.8,-39.7,-47.8,-53.3,-47,-66.5,-68.5,-58.75,-58.05,-69.71,-68.15,-65.85,-80.37,-67.95,'No Data',-83.56,-78.65,-82.4}; 

% Small_Variance 
zRef_Ex_1_Var = {0.49,0.24,0.6,0.29,4.8,7.32,1.44,15.49,1.44,0.89,3.09,24.06,0.52,0.6,14.62,1.18,4.78,0.27,1.53,0.6}; 
zRef_Ex_2_Var = {57.97,0.17,0.85,0.24,1.06,1.25,3.69,0.41,0.19,0.22,0.24,1.67,9.08,'No Data',1.44,1.72,0.16,1.08,0.96,'No Data'}; 
zRef_Ex_3_Var = {216.96,55.15,1.19,187.65,1.49,5.29,45.45,5.39,2.35,4.99,52.61,1.83,29.43,4.41,0.22,20.04,114.33,0,5.43,6.15}; 
zRef_Ex_4_Var = {62.25,0.44,72.46,32.71,34.46,10.11,1,5.45,0.36,40.19,1.35,13.03,2.23,2.63,0.23,5.85,'No Data',6.91,1.13,1.44}; 

% Small_GVariance 
Ref_Ex_Group_Var = {128.47,33.09,55.21,96.3,28.2,14.83,34.13,22.74,3.59,46.75,28.34,16.28,29.69,14.69,11.52,21.39,63.51,4.92,4.55,3.1}; 

% Wifi_Mean 
zWifi_Ex_1_Mean = {-54,-57.5,-47.9,-45.25,-53.4,-58.25,-50.05,-69.05,-71.85,-55.75,-65.5,-81.5,-65.4,-63.39,-81.74,-71.6,-87.22,'No Data',-75.88,'No Data'}; 
zWifi_Ex_2_Mean = {-53.3,-53.05,-50.25,-37.7,-50.95,-59.2,-59.8,-66.63,-63.25,-53.5,-63.55,-66.25,-64.55,-62.7,-85.35,-68.3,'No Data',-83.63,-74.5,-88}; 

% Wifi_Variance 
zWifi_Ex_1_Var = {25.4,2.55,4.09,15.39,9.64,0.79,2.65,0.45,32.53,29.29,10.15,9.65,19.64,18.9,0.72,6.84,0.73,'No Data',0.1,'No Data'}; 
zWifi_Ex_2_Var = {53.41,0.85,48.29,94.41,1.05,15.16,2.26,2.76,14.89,97.35,1.45,70.89,9.35,0.41,0.93,12.61,'No Data',6.34,51.63,0}; 

% Wifi_GVariance 
Wifi_Ex_Group_Var = {39.53,6.65,27.57,69.15,6.84,8.2,26.22,3.03,42.2,64.58,6.75,98.41,14.67,9.29,4.08,12.45,0.73,6.34,25.56,0}; 

% SigGen_Mean 
zSig_Ex_1_Mean = {-42.6,-56.4,-41.6,-41.25,-53.79,-57.44,-55.55,'No Data','No Data',-53.45,-61.8,'No Data',-61.42,-69.05,'No Data',-67.25,'No Data','No Data','No Data','No Data'}; 
zSig_Ex_2_Mean = {-41.15,-61.35,-61.25,-44.55,-51.8,-58.35,-56.37,-61.54,-66,-57.25,-64.63,'No Data',-58.59,-66.89,'No Data','No Data','No Data','No Data','No Data','No Data'}; 

% SigGen_Variance 
zSig_Ex_1_Var = {0.54,1.34,2.04,0.89,0.48,0.25,5.95,'No Data','No Data',0.65,0.46,'No Data',12.03,0.55,'No Data',1.44,'No Data','No Data','No Data','No Data'}; 
zSig_Ex_2_Var = {0.83,23.13,2.39,0.75,4.16,1.93,4.34,35.79,0,7.59,0.76,'No Data',4.24,1.57,'No Data','No Data','No Data','No Data','No Data','No Data'}; 

% SigGen_GVariance 
Sig_Ex_Group_Var = {1.21,18.36,98.74,3.54,3.36,1.34,5.33,35.79,0,7.73,2.61,'No Data',10.35,2.21,'No Data',1.44,'No Data','No Data','No Data','No Data'}; 

% Fuse all the datasets to one
dataSet = {zRef_Ex_1_Mean, 
        zRef_Ex_2_Mean,
        zRef_Ex_3_Mean,
        zRef_Ex_4_Mean,
        zWifi_Ex_1_Mean,
        zWifi_Ex_2_Mean,
        zSig_Ex_1_Mean,
        zSig_Ex_2_Mean,
        zRef_Ex_1_Var, 
        zRef_Ex_2_Var,
        zRef_Ex_3_Var,
        zRef_Ex_4_Var,
        zWifi_Ex_1_Var,
        zWifi_Ex_2_Var,
        zSig_Ex_1_Var,
        zSig_Ex_2_Var,
        Ref_Ex_Group_Var,
        Wifi_Ex_Group_Var,
        Sig_Ex_Group_Var
        };

% Titles for the plot
expTitle = {            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 1 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 2 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 3 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 4 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 1 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 2 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 1 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 2 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 1 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 2 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 3 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiments 4 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 1 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 2 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 1 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Experiment 2 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:ef : Group Variance of Reference Scenario',
            'Access Point : CREW 64:70:02:3e:aa:ef : Group Variance of Interference Scenario 2',
            'Access Point : CREW 64:70:02:3e:aa:ef : Group Variance of Interference Scenario 1'
};

% File names to be generated
fileName = {'ef_Ref_Ex_1_Mean',
            'ef_Ref_Ex_2_Mean',
            'ef_Ref_Ex_3_Mean',
            'ef_Ref_Ex_4_Mean',
            'ef_Wifi_Ex_1_Mean',
            'ef_Wifi_Ex_2_Mean',
            'ef_Sig_Ex_1_Mean',
            'ef_Sig_Ex_2_Mean',
            'ef_Ref_Ex_1_Variance',
            'ef_Ref_Ex_2_Variance',
            'ef_Ref_Ex_3_Variance',
            'ef_Ref_Ex_4_Variance',
            'ef_Wifi_Ex_1_Variance',
            'ef_Wifi_Ex_2_Variance',
            'ef_Sig_Ex_1_Variance',
            'ef_Sig_Ex_2_Variance',
            'ef_Ref_Group_Variance',
            'ef_Wifi_Group_Variance',
            'ef_Sig_Group_Variance'
};

noData = 'No Data';
numberOfDataSet = size(dataSet,1);

for i =  1:numberOfDataSet
    %Select the dataset
    selectedDataSet = dataSet{i};            
    xX = [];
    yY = [];
    zZ = [];
    
    %creat a new dataset without elimnated
    for p = 1:20
        res = strcmp(noData, selectedDataSet(p));
        if res == 0        
            zZ = [zZ selectedDataSet(p)];
            xX = [xX x(p)];
            yY = [yY y(p)];
        end
    end
    
    %convert the cell array to matrix array
    zZ = cell2mat(zZ);

    % Construct the interpolant function
    F = TriScatteredInterp(xX',yY',zZ');

    % Sample uniformly the surface for matrices (qx, qy, qz)
    tx = 0:0.1:32; 
    ty = 0:0.1:15;

    % Create a mesh
    [qx, qy] = meshgrid(tx, ty); 
    qz = F(qx, qy);

    % Plot using contour function
    [C,h] = contourf(qx, qy, qz);

    % Creat colormap and colorbar
    colormap(autumn)
    colorbar

    % Draw points
    hold on; 
    h = plot(x,y,'ko'); 
    set(h, 'Markersize',10);
    h = plot(4,14.8,'k.'); 
    set(h, 'Markersize',30);
    
    if i == 7 || i == 8 || i == 15 || i == 16 || i == 19        
        h = plot(21,1,'k.'); 
        set(h, 'Markersize',30);
        text(13,1, 'Signal Generator \rightarrow')
    end
    
    if i == 5 || i == 6 || i == 13 || i == 14 || i == 18        
        h = plot(11,0.7,'k.');  
        set(h, 'Markersize',30);
        text(3,0.7, 'UDP Transmitter \rightarrow')
        h = plot(21,14.8,'k.');     
        set(h, 'Markersize',30);
        text(22,14.8, '\leftarrow TCP Transmitter')
        h = plot(18,0.7,'k.');  
        set(h, 'Markersize',30);
        text(19, 0.7, '\leftarrow UDP & TCP Receiver')
    end
    
    hold off

    % Draw Point lables
    text(5,14.5, '\leftarrow Access Point')

    % Draw plot lables
    grid
    xlabel('X-coordinate [m]');
    ylabel('Y-coordinate [m]');
    title(expTitle{i});
    
    %save as files
    saveas(h, fileName{i} ,'jpg')

end