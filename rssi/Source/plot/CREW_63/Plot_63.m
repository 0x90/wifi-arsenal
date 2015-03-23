% Measurement points
x = [2.02,2.17,3.51,5.16,5.39,8.48,9.81,11.57,11.57,14.48,16.12,17.56,17.59,20.54,20.71,22.08,23.9,26.53,26.68,30.28];
y = [10.98,4.98,9.02,10.94,5.06,1.93,9.02,5.06,1.89,10.95,9.02,5.06,10.95,10.94,1.65,9.02,1.67,5.39,9.03,1.67];

% Datasets

% Ref_Mean 
zRef_Ex_1_Mean = {-65.07,-77.27,-64,-47.2,-75.93,-74.87,-50.87,-62.87,-64.6,-47.93,-51.73,-62.33,-39.33,-28.33,-58.6,-43.6,-66.53,-71.93,-60.47,-72.4}; 
zRef_Ex_2_Mean = {-70.75,-81.91,-72.08,-59.67,-69.83,-74.83,-59.58,-73.67,-69.75,-49.75,-48.92,-61.25,-44.08,-62.75,-62.75,-52.75,-77.58,-76.5,-52.92,-73}; 
zRef_Ex_3_Mean = {-68.7,-77.4,-72.65,-62.5,-73.2,-78.15,-67.85,-73.6,-73.95,-53.15,-51.7,-67.7,-41.2,-43.55,-63.6,-50.5,-71.42,-71.85,-59.15,-70.55}; 
zRef_Ex_4_Mean = {-75.45,-82.8,-74.8,-63.55,-77,-82.83,-66,-71.15,-66.35,-51.1,-49.95,-64.3,-39.05,-37.95,-66.55,-46.35,-68.47,-70.6,-61.15,-76.15}; 

% Ref_Variance 
zRef_Ex_1_Var = {0.6,0.46,1.33,0.96,1.13,0.38,1.18,0.25,1.17,0.2,0.33,2.22,0.36,8.49,62.77,0.37,2.38,0.6,22.12,0.77}; 
zRef_Ex_2_Var = {0.35,0.45,0.91,1.56,2.31,4.97,2.08,0.22,1.69,0.19,16.41,1.52,6.91,0.85,0.85,2.69,10.24,15.25,3.08,0.5}; 
zRef_Ex_3_Var = {0.41,21.34,6.23,14.15,1.86,1.43,0.43,22.64,6.37,0.23,1.61,5.11,0.46,0.25,40.14,0.45,1.4,48.03,10.33,18.85}; 
zRef_Ex_4_Var = {9.15,1.66,36.16,2.45,5.6,0.25,1.4,19.03,30.43,0.39,0.45,3.61,0.15,33.35,1.75,0.73,37.51,1.94,4.83,1.53}; 

% Ref_GVariance 
Ref_Ex_Group_Var = {17.9,13.82,29.35,46.52,9.6,12.1,44.97,30.37,25.24,3.97,4.9,9.35,4.85,136.62,34.88,11.96,28.15,21.89,18.52,11.17}; 

% Wifi_Mean 
zWifi_Ex_1_Mean = {-72.25,-78.35,-70.9,-61.9,-77.37,-83.23,-62.6,-73.6,-72.5,-54.55,-53.95,-60.6,-45.85,-39.3,-63.85,-52.55,-69.5,-74.85,-58.9,-70.21}; 
zWifi_Ex_2_Mean = {-72.5,-79.55,-71,-67.85,-75.79,-79.55,-61.9,-75.32,-69.85,-50.85,-53.45,-57.3,-49.85,-38.6,-62.45,-46,-73.3,-74.05,-57.95,-69.05}; 

% Wifi_Variance 
zWifi_Ex_1_Var = {17.39,23.73,35.59,9.39,0.76,0.18,1.84,32.24,1.85,0.55,35.25,1.74,58.53,0.31,6.43,0.45,2.65,3.13,0.49,3.64}; 
zWifi_Ex_2_Var = {8.15,0.85,5,1.93,1.85,7.95,12.49,0.32,9.53,0.33,1.75,9.81,36.63,0.24,4.15,0.1,1.11,32.85,0.35,1.05}; 

% Wifi_GVariance 
Wifi_Ex_Group_Var = {12.78,12.65,20.3,14.51,1.93,8.12,7.29,17.43,7.44,3.86,18.56,8.5,51.58,0.4,5.78,11,5.49,18.15,0.64,2.65}; 

% SigGen_Mean 
zSig_Ex_1_Mean = {-73.4,-80.92,-74.15,-65.25,'No Data','No Data',-64.35,'No Data','No Data',-51.3,-47.65,'No Data',-46.65,-39.6,'No Data',-48.58,'No Data','No Data',-58.71,'No Data'}; 
zSig_Ex_2_Mean = {-75.9,'No Data',-67.89,-65.32,'No Data','No Data',-64.95,-62,'No Data',-53.4,-53,'No Data',-47.15,-32.75,'No Data',-50.3,'No Data','No Data',-61,'No Data'}; 

% SigGen_Variance 
zSig_Ex_1_Var = {3.24,0.69,2.13,3.39,'No Data','No Data',2.13,'No Data','No Data',49.21,2.23,'No Data',1.23,0.94,'No Data',4.56,'No Data','No Data',1.03,'No Data'}; 
zSig_Ex_2_Var = {14.89,'No Data',0.09,1.06,'No Data','No Data',0.95,0,'No Data',0.44,0,'No Data',0.13,7.99,'No Data',2.61,'No Data','No Data',0.15,'No Data'}; 

% SigGen_GVariance 
Sig_Ex_Group_Var = {10.63,0.69,10.91,2.25,'No Data','No Data',1.63,0,'No Data',25.93,8.31,'No Data',0.74,16.19,'No Data',4.3,'No Data','No Data',1.94,'No Data'}; 


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
expTitle = {            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 1 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 2 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 3 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 4 - Reference Scenario - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 1 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 2 - Interference Scenario 2 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 1 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 2 - Interference Scenario 1 - Mean of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 1 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 2 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 3 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiments 4 - Reference Scenario - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 1 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 2 - Interference Scenario 2 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 1 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Experiment 2 - Interference Scenario 1 - Variance of RSSI',
            'Access Point : CREW 64:70:02:3e:9f:63 : Group Variance of Reference Scenario',
            'Access Point : CREW 64:70:02:3e:9f:63 : Group Variance of Interference Scenario 2',
            'Access Point : CREW 64:70:02:3e:9f:63 : Group Variance of Interference Scenario 1'
};

% File names to be generated
fileName = {'63_Ref_Ex_1_Mean',
            '63_Ref_Ex_2_Mean',
            '63_Ref_Ex_3_Mean',
            '63_Ref_Ex_4_Mean',
            '63_Wifi_Ex_1_Mean',
            '63_Wifi_Ex_2_Mean',
            '63_Sig_Ex_1_Mean',
            '63_Sig_Ex_2_Mean',
            '63_Ref_Ex_1_Variance',
            '63_Ref_Ex_2_Variance',
            '63_Ref_Ex_3_Variance',
            '63_Ref_Ex_4_Variance',
            '63_Wifi_Ex_1_Variance',
            '63_Wifi_Ex_2_Variance',
            '63_Sig_Ex_1_Variance',
            '63_Sig_Ex_2_Variance',
            '63_Ref_Group_Variance',
            '63_Wifi_Group_Variance',
            '63_Sig_Group_Variance'
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
    h = plot(21.5,14.8,'k.'); 
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
    text(14.5,14.6, 'Access Point \rightarrow')

    % Draw plot lables
    grid
    xlabel('X-coordinate [m]');
    ylabel('Y-coordinate [m]');
    title(expTitle{i});
    
    %save as files
    saveas(h, fileName{i} ,'jpg')

end