% Measurement points
x = [2.02,2.17,3.51,5.16,5.39,8.48,9.81,11.57,11.57,14.48,16.12,17.56,17.59,20.54,20.71,22.08,23.9,26.53,26.68,30.28];
y = [10.98,4.98,9.02,10.94,5.06,1.93,9.02,5.06,1.89,10.95,9.02,5.06,10.95,10.94,1.65,9.02,1.67,5.39,9.03,1.67];

% Datasets

% Small_Mean 
zRef_Ex_1_Mean = {-56.87,-37.4,-46.2,-51.13,-37.8,-44,-50.47,-46.67,-45.93,-69.8,-65.73,-51.07,-68.27,-74.87,-58.53,-70.67,-58,-62.47,-76.93,-65.07}; 
zRef_Ex_2_Mean = {-59.5,-35.83,-50.5,-63.42,-39,-43.5,-58.08,-55.58,-52.67,-71.83,-69.75,-65.67,-77.75,'No Data',-63,-78.92,-68,-71.08,-76.67,-69}; 
zRef_Ex_3_Mean = {-53.5,-49.25,-56.05,-61.2,-43.15,-39.85,-58,-55.35,-55.15,-74.47,-69.1,-57.9,-80.58,-81.25,-65.05,-76.55,-66.8,-67.37,-81.95,-72.2}; 
zRef_Ex_4_Mean = {-58.4,-40.7,-55.95,-58.8,-51.45,-46.45,-47.8,-52.1,-55.35,-72.85,-63.7,-61.25,-72.55,-84.16,-67.95,-75.75,-65.75,-75.5,-79.11,-77.25}; 

% Small_Variance 
zRef_Ex_1_Var = {7.58,112.24,1.09,0.25,0.43,1.47,0.25,1.56,0.06,0.69,3.66,0.33,0.2,0.65,0.52,1.02,0.8,0.92,1.26,0.86}; 
zRef_Ex_2_Var = {10.92,3.64,46.75,2.08,0.17,1.58,20.41,2.41,0.39,0.81,2.52,1.89,2.52,'No Data',0.17,0.58,0.5,1.08,1.89,0.17}; 
zRef_Ex_3_Var = {0.25,57.49,1.25,34.66,0.43,0.93,1.3,0.73,20.33,11.3,0.39,18.19,0.24,2.59,40.68,0.45,0.26,21.18,0.95,26.36}; 
zRef_Ex_4_Var = {9.24,94.71,1.25,1.26,50.85,22.45,1.96,8.69,2.93,1.43,1.61,0.89,44.35,1.29,13.75,29.19,23.39,11.75,2.2,10.79}; 

% Small_GVariance 
Ref_Ex_Group_Var = {11.81,98.83,26.18,29.82,45.2,14.21,26.2,15.38,21.16,6.88,8.13,29.97,36.44,15.32,28.04,16.84,20.97,33.97,6.15,31.71}; 

% Wifi_Mean 
zWifi_Ex_1_Mean = {-58.35,-42.6,-54.1,-53.3,-44.3,-43.6,-56.25,-54.35,-48.15,-71.65,-70.55,-56.15,-77.95,-84.75,-64,-76.5,-70.65,-62.4,-76.35,-63.7}; 
zWifi_Ex_2_Mean = {-55.85,-39.1,-50.4,-54.25,-46.05,-49,-53.6,-51.4,-52.5,-73.74,-68.9,-60.35,-75.2,-81.9,-63.8,-73.55,-71.55,-69,-75.6,-73.35}; 

% Wifi_Variance 
zWifi_Ex_1_Var = {34.03,28.64,4.59,3.81,19.41,2.04,33.39,2.33,1.83,6.93,0.25,1.93,4.05,5.19,1.1,0.25,58.93,4.94,1.23,0.21}; 
zWifi_Ex_2_Var = {4.63,0.29,32.74,1.69,0.45,0.2,1.84,2.44,22.25,21.56,20.19,8.93,0.66,4.19,0.56,0.45,2.75,1.7,67.84,32.83}; 

% Wifi_GVariance 
Wifi_Ex_Group_Var = {20.89,17.53,22.09,2.97,10.69,8.41,19.37,4.56,16.77,15.15,10.9,9.84,4.24,6.72,0.84,2.52,31.04,14.21,34.67,39.8}; 

% SigGen_Mean 
zSig_Ex_1_Mean = {-51.95,-39.9,-57.2,-60.5,-46,-41.22,-64.2,-54.45,-58.75,-67.55,-67.56,'No Data',-73.05,'No Data','No Data','No Data','No Data','No Data','No Data','No Data'}; 
zSig_Ex_2_Mean = {-50.45,-38.8,-51.2,-53.15,-37.58,-49.79,-53.6,-56.9,-52,-71.6,-51,'No Data','No Data','No Data','No Data','No Data','No Data','No Data','No Data','No Data'}; 

% SigGen_Variance 
zSig_Ex_1_Var = {2.35,1.09,12.46,4.75,5.16,3.84,0.16,0.45,0.44,2.35,32.36,'No Data',15.05,'No Data','No Data','No Data','No Data','No Data','No Data','No Data'}; 
zSig_Ex_2_Var = {0.75,34.26,1.96,2.13,2.56,1.85,0.94,0.89,0,2.64,0,'No Data','No Data','No Data','No Data','No Data','No Data','No Data','No Data','No Data'}; 

% SigGen_GVariance 
Sig_Ex_Group_Var = {2.11,17.98,16.21,16.94,21.59,21.15,28.64,2.17,2.93,6.59,67.25,'No Data',15.05,'No Data','No Data','No Data','No Data','No Data','No Data','No Data'}; 

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
expTitle = {            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 1 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 2 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 3 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 4 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 1 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 2 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 1 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 2 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 1 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 2 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 3 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiments 4 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 1 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 2 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 1 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Experiment 2 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Group Variance of Reference Scenario',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Group Variance of Interference Scenario 2',
            'Access Point : CREW 64:70:02:3e:aa:d9 : Group Variance of Interference Scenario 1'
};

% File names to be generated
fileName = {'d9_Ref_Ex_1_Mean',
            'd9_Ref_Ex_2_Mean',
            'd9_Ref_Ex_3_Mean',
            'd9_Ref_Ex_4_Mean',
            'd9_Wifi_Ex_1_Mean',
            'd9_Wifi_Ex_2_Mean',
            'd9_Sig_Ex_1_Mean',
            'd9_Sig_Ex_2_Mean',
            'd9_Ref_Ex_1_Variance',
            'd9_Ref_Ex_2_Variance',
            'd9_Ref_Ex_3_Variance',
            'd9_Ref_Ex_4_Variance',
            'd9_Wifi_Ex_1_Variance',
            'd9_Wifi_Ex_2_Variance',
            'd9_Sig_Ex_1_Variance',
            'd9_Sig_Ex_2_Variance',
            'd9_Ref_Group_Variance',
            'd9_Wifi_Group_Variance',
            'd9_Sig_Group_Variance'
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
    h = plot(2,0.7,'k.'); 
    set(h, 'Markersize',30);
    
    if i == 7 || i == 8 || i == 15 || i == 16 || i == 19        
        h = plot(21,1,'k.'); 
        set(h, 'Markersize',30);
        text(13,1, 'Signal Generator \rightarrow')
    end
    
    if i == 5 || i == 6 || i == 13 || i == 14 || i == 18        
        h = plot(11,0.7,'k.');  
        set(h, 'Markersize',30);
        text(3,1.3, 'UDP Transmitter \rightarrow')
        h = plot(21,14.8,'k.');     
        set(h, 'Markersize',30);
        text(22,14.8, '\leftarrow TCP Transmitter')
        h = plot(18,0.7,'k.');  
        set(h, 'Markersize',30);
        text(19, 0.7, '\leftarrow UDP & TCP Receiver')
    end
    
    hold off

    % Draw Point lables
    text(3,0.7, '\leftarrow Access Point')

    % Draw plot lables
    grid
    xlabel('X-coordinate [m]');
    ylabel('Y-coordinate [m]');
    title(expTitle{i});
    
    %save as files
    saveas(h, fileName{i} ,'jpg')

end