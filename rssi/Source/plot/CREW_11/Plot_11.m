% Measurement points
x = [2.02,2.17,3.51,5.16,5.39,8.48,9.81,11.57,11.57,14.48,16.12,17.56,17.59,20.54,20.71,22.08,23.9,26.53,26.68,30.28];
y = [10.98,4.98,9.02,10.94,5.06,1.93,9.02,5.06,1.89,10.95,9.02,5.06,10.95,10.94,1.65,9.02,1.67,5.39,9.03,1.67];

% Datasets

% Small_Mean 
zRef_Ex_1_Mean = {-79.53,-62.27,-68.47,-79.73,-61.67,-58.33,-71.33,-47.67,-58.53,-67,-61.4,-47.87,-67.87,-68.13,-43.8,-55.93,-38.53,-41.93,-48.47,-24.87}; 
zRef_Ex_2_Mean = {-86.5,-73.08,-73.92,-83.9,-62.42,-66.42,-71.25,-49.67,-60.5,-78.08,-61.91,-50.08,-70.83,'No Data',-59.33,-57.92,-53.75,-43.25,-52.5,-26.42}; 
zRef_Ex_3_Mean = {-86.83,-79.95,-77.55,-84.7,-65.53,-71.3,-78.9,-58.8,-57.05,-75.76,-64.7,-54.35,-70.3,-68.2,-47.7,-59.6,-51.2,-39.9,-53.8,-15.55}; 
zRef_Ex_4_Mean = {-86,-75.35,-74.6,-77.85,-63.1,-64.9,-77.07,-57.65,-63.84,-83.41,-66.7,-52.55,-78.5,-64.2,-47.45,-57.15,-51.05,-39.25,-53.65,-36.25}; 

% Small_Variance 
zRef_Ex_1_Var = {0.38,0.33,0.52,1.13,0.22,43.69,1.42,0.36,0.52,2.4,0.51,0.12,2.92,0.38,0.16,0.33,1.05,0.86,1.32,0.12}; 
zRef_Ex_2_Var = {1.58,0.24,1.08,1.29,0.74,0.91,18.85,54.22,9.92,2.08,0.08,3.58,1.64,'No Data',143.39,38.58,209.52,65.35,46.75,0.24}; 
zRef_Ex_3_Var = {0.81,0.79,1.25,5.71,2.14,0.81,7.29,28.56,1.15,14.53,1.81,6.33,1.31,2.76,37.01,1.04,228.16,0.19,9.06,0.25}; 
zRef_Ex_4_Var = {0,8.23,15.14,102.23,1.39,3.49,7.21,4.33,11.19,0.24,2.61,20.25,24.65,2.26,56.75,0.83,59.05,67.49,74.53,381.89}; 

% Small_GVariance 
Ref_Ex_Group_Var = {12.3,44.51,15.93,42.5,3.41,33.01,20.13,42.7,12.91,41.17,6.08,14.66,26.15,5.58,80.08,9.41,154.71,34.42,38.13,178.36}; 

% Wifi_Mean 
zWifi_Ex_1_Mean = {-87.05,-70.5,-79.45,-78.2,-66.8,-70.35,-73.16,-57.25,-60.35,-72.1,-67.35,-59.55,-70.65,-65.5,-55.35,-62.8,-45.55,-45.4,-58.45,-31.35}; 
zWifi_Ex_2_Mean = {-84.5,-78.47,-77.55,-81.3,-72.1,-70.15,-71.75,-56.85,-61,-80.85,-66.95,-51.15,-70.55,-71.95,-56.6,-58.15,-45.25,-50.5,-55,-35.95}; 

% Wifi_Variance 
zWifi_Ex_1_Var = {0.05,9.35,4.15,0.16,2.56,0.83,0.34,3.99,14.23,132.09,9.03,54.95,13.23,30.45,0.93,25.36,0.85,40.54,14.85,0.23}; 
zWifi_Ex_2_Var = {16.75,2.6,2.35,0.81,5.89,1.53,4.69,1.13,5.6,22.33,3.85,43.93,1.95,2.95,2.04,6.93,1.59,62.95,76.3,142.85}; 

% Wifi_GVariance 
Wifi_Ex_Group_Var = {10.02,22.03,4.15,2.89,11.25,1.19,3.07,2.6,10.02,96.35,6.48,67.08,7.59,27.1,1.87,21.55,1.24,58.25,48.55,76.83}; 

% SigGen_Mean 
zSig_Ex_1_Mean = {'No Data',-76,-71.2,-86.2,-64,'No Data',-71.35,'No Data',-55.35,-52.46,-73,'No Data',-69.4,-70.67,-52,-57,'No Data',-40,-56,-47.68}; 
zSig_Ex_2_Mean = {77,74,'No Data','No Data',67.67,55.74,67.87,54.94,54,78.57,'No Data','No Data','No Data',68,'No Data',54.07,46,38,55.79,51.25}; 

% SigGen_Variance 
zSig_Ex_1_Var = {'No Data',0,0.66,0.69,0,'No Data',2.23,'No Data',4.82,109.48,0,'No Data',0.64,0.22,0,0,'No Data',0,0,209.58}; 
zSig_Ex_2_Var = {0,0,'No Data','No Data',0.22,28.09,0.12,0.06,0,1.1,'No Data','No Data','No Data',0,'No Data',0.06,0,0,5.75,137.99}; 

% SigGen_GVariance 
Sig_Ex_Group_Var = {0,0.66,0.66,0.69,1.16,28.09,4.29,0.06,4.18,226.64,0,'No Data',0.64,1.73,0,2.17,0,0.96,4.21,176.04}; 


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
expTitle = {            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 1 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 2 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 3 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 4 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 1 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 2 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 1 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 2 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 1 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 2 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 3 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiments 4 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 1 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 2 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 1 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Experiment 2 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:aa:11 : Group Variance of Reference Scenario',
            'Access Point : CREW 64:70:02:3e:aa:11 : Group Variance of Interference Scenario 2',
            'Access Point : CREW 64:70:02:3e:aa:11 : Group Variance of Interference Scenario 1'
};

% File names to be generated
fileName = {'11_Ref_Ex_1_Mean',
            '11_Ref_Ex_2_Mean',
            '11_Ref_Ex_3_Mean',
            '11_Ref_Ex_4_Mean',
            '11_Wifi_Ex_1_Mean',
            '11_Wifi_Ex_2_Mean',
            '11_Sig_Ex_1_Mean',
            '11_Sig_Ex_2_Mean',
            '11_Ref_Ex_1_Variance',
            '11_Ref_Ex_2_Variance',
            '11_Ref_Ex_3_Variance',
            '11_Ref_Ex_4_Variance',
            '11_Wifi_Ex_1_Variance',
            '11_Wifi_Ex_2_Variance',
            '11_Sig_Ex_1_Variance',
            '11_Sig_Ex_2_Variance',
            '11_Ref_Group_Variance',
            '11_Wifi_Group_Variance',
            '11_Sig_Group_Variance'
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
    h = plot(31,0.7,'k.'); 
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
        text(18, 1.3, '\leftarrow UDP & TCP Receiver')
    end
    
    hold off

    % Draw Point lables
    text(24,0.7, 'Access Point \rightarrow')

    % Draw plot lables
    grid
    xlabel('X-coordinate [m]');
    ylabel('Y-coordinate [m]');
    title(expTitle{i});
    
    %save as files
    saveas(h, fileName{i} ,'jpg')

end