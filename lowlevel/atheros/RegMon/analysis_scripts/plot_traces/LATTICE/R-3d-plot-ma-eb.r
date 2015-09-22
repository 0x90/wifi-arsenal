require(lattice)

grid=list();
grid$arr_mod=vector();
grid$arr_tx=vector();
grid$thr=vector();

filename="trace-ma-eb"

data = read.table(filename);

len = length(data[[1]])

for( i in 1:len )
{

	grid$arr_mod=c(grid$arr_mod, data[[1]][[i]])
	grid$arr_tx=c(grid$arr_tx, data[[2]][[i]])
	grid$arr_thr=c(grid$arr_thr, data[[3]][[i]])

}

wireframe( arr_thr~arr_mod * arr_tx, grid, drape=TRUE, aspect = c(1, 0.4),  colorkey=TRUE, default.scales = list(distance = c(1, 1, 1), arrows=FALSE), screen = list(z = -40, x = -60) )

