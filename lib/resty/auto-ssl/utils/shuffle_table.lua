return function(tbl)
  for i = #tbl, 1, -1 do
    local rand = math.random(i)
    tbl[i], tbl[rand] = tbl[rand], tbl[i]
  end
  return tbl
end
